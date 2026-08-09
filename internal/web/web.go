// Package web serves the server-rendered HTML UI: login, app list, app page
// with uploads and latest-version management. Templates are embedded.
package web

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/files"
	"apprepo/internal/naming"
	"apprepo/internal/platform"
	"apprepo/internal/store"
)

//go:embed templates
var tplFS embed.FS

const (
	csrfCookie = "apprepo_csrf"
	csrfField  = "csrf_token"

	// Лимиты не-file частей multipart-формы (ждём csrf_token/version/sha256).
	maxUploadFields = 8
	maxFieldBytes   = 4096
)

type handlers struct {
	st   *store.Store
	fs   *files.Storage
	auth *auth.Auth
	cfg  config.Config
	tpl  map[string]*template.Template
}

// Register mounts all UI routes on mux. Every route except /login requires a
// session and a permission; every POST is CSRF-protected (double-submit cookie).
func Register(mux *http.ServeMux, st *store.Store, fst *files.Storage, a *auth.Auth, cfg config.Config) {
	h := &handlers{st: st, fs: fst, auth: a, cfg: cfg, tpl: map[string]*template.Template{}}
	for _, name := range []string{"login", "index", "app", "users", "forbidden"} {
		h.tpl[name] = template.Must(template.ParseFS(tplFS,
			"templates/layout.html", "templates/"+name+".html"))
	}
	// Свой экземпляр Auth: отказ 403 в UI — HTML-страница, а не JSON API.
	// Auth без состояния, поэтому ответ для api.Register это не меняет.
	ui := &auth.Auth{Store: a.Store, Forbidden: h.forbidden}
	// guard — единственный способ повесить UI-маршрут: сессия, затем допуск в
	// интерфейс (deployer его не проходит), затем право самой операции.
	guard := func(p auth.Permission, next http.Handler) http.Handler {
		return ui.RequireSession(ui.Require(auth.PermUI, ui.Require(p, next)))
	}
	form := func(p auth.Permission, fn http.HandlerFunc) http.Handler {
		return guard(p, csrf(fn))
	}
	mux.HandleFunc("GET /login", h.loginForm)
	mux.Handle("POST /login", csrf(http.HandlerFunc(h.loginPost)))
	// Выход намеренно без PermUI: иначе deployer, которого интерфейс не пускает,
	// не смог бы погасить сессию с той самой страницы-объяснения.
	mux.Handle("POST /logout", ui.RequireSession(csrf(http.HandlerFunc(h.logout))))
	mux.Handle("GET /{$}", guard(auth.PermUI, http.HandlerFunc(h.index)))
	mux.Handle("GET /apps/{name}", guard(auth.PermUI, http.HandlerFunc(h.appPage)))
	mux.Handle("POST /apps", form(auth.PermApp, h.createApp))
	// CSRF для multipart проверяется внутри хендлера: тело читается потоково
	// по частям, а не через ParseForm (иначе файл лёг бы во временный буфер).
	mux.Handle("POST /apps/{name}/versions", guard(auth.PermVersion, http.HandlerFunc(h.upload)))
	// Закрепление latest — PermVersion, как и в API: developer и так двигает
	// latest неявно (залитая версия со старшим semver становится latest сама),
	// поэтому запрещать ему явное закрепление непоследовательно.
	mux.Handle("POST /apps/{name}/latest", form(auth.PermVersion, h.setLatest))
	// HTML-формы не умеют PATCH/DELETE, поэтому правка и удаление — тоже POST.
	mux.Handle("POST /apps/{name}/edit", form(auth.PermApp, h.editApp))
	mux.Handle("POST /apps/{name}/delete", form(auth.PermApp, h.deleteApp))
	mux.Handle("POST /apps/{name}/versions/{version}/delete",
		form(auth.PermVersion, h.deleteVersion))
	// Ручная простановка платформы — то же право, что и заливка версии: это
	// правка её же карточки, и в API она пойдёт под PermVersion (T25).
	mux.Handle("POST /apps/{name}/versions/{version}/platform",
		form(auth.PermVersion, h.setVersionPlatform))
	mux.Handle("POST /password", form(auth.PermUI, h.changeOwnPassword))
	mux.Handle("GET /users", guard(auth.PermUserAdmin, http.HandlerFunc(h.usersPage)))
	mux.Handle("POST /users", form(auth.PermUserAdmin, h.createUser))
	mux.Handle("POST /users/{id}/role", form(auth.PermUserAdmin, h.setUserRole))
	mux.Handle("POST /users/{id}/disabled", form(auth.PermUserAdmin, h.setUserDisabled))
	mux.Handle("POST /users/{id}/password", form(auth.PermUserAdmin, h.resetUserPassword))
	mux.Handle("POST /users/{id}/delete", form(auth.PermUserAdmin, h.deleteUser))
}

// forbidden renders the UI answer to a denied Require instead of the JSON
// default. deployer lands here on every page: its role has no PermUI at all,
// and a 403 page is exactly what keeps it out of a loop with /login — the
// session is valid, so RequireSession has nothing to redirect for.
func (h *handlers) forbidden(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusForbidden, "forbidden", h.baseView(w, r))
}

// --- CSRF (double-submit cookie, без внешних библиотек) ---

// ensureCSRF returns the CSRF token from the cookie, setting a new one first
// if the client has none yet. Called when rendering pages with forms.
func (h *handlers) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value
	}
	buf := make([]byte, 32)
	rand.Read(buf) // crypto/rand.Read не возвращает ошибок начиная с go1.24
	tok := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// csrfOK reports whether the submitted token matches the cookie.
func csrfOK(r *http.Request, token string) bool {
	c, err := r.Cookie(csrfCookie)
	return err == nil && token != "" &&
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) == 1
}

// csrf guards urlencoded POST forms; multipart uploads check inside the handler.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil || !csrfOK(r, r.PostForm.Get(csrfField)) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- rendering ---

type appRow struct {
	App           *store.App
	Latest        *store.Version
	VersionsCount int
}

type verRow struct {
	V        *store.Version
	IsLatest bool
	// OS и Arch — половинки V.Platform для выпадающих списков строки ("any"
	// целиком уезжает в OS, пустая платформа даёт две пустые строки).
	OS   string
	Arch string
	// DialogOpen — диалог платформы этой строки открывается сразу: страница
	// пришла отказом на его отправку. Считается здесь, чтобы id модалки не
	// собирался вторым местом в разметке.
	DialogOpen bool
}

// perms is what the current role may do, resolved once per render. Шаблоны
// спрашивают право (.Can.App), а не имя роли: матрица прав живёт в auth, и
// сравнение строк в разметке разъехалось бы с ней при первом же изменении.
type perms struct {
	UI        bool
	Version   bool
	App       bool
	UserAdmin bool
}

// view is the single template data bag; each page uses its subset.
type view struct {
	User     *store.User
	Can      perms
	CSRF     string
	Error    string
	Notice   string
	Next     string
	Apps     []appRow
	App      *store.App
	Versions []verRow
	Latest   *store.Version
	Pinned   bool
	Users    []*store.User
	Roles    []auth.Role
	// Словарь платформ для выпадающих списков — из internal/platform, а не
	// списком в разметке: копия разъехалась бы с тем, что принимает Parse.
	PlatformOS      []string
	PlatformArch    []string
	PlatformSpecial []platformOption
	// Legacy — учётки со старым, но рабочим именем: id → имя в кавычках;
	// Broken — то же для имён с двоеточием, которые по Basic не входят вовсе
	// (см. legacyNames). Пустая карта означает «таких нет», и страница ничего
	// не показывает.
	Legacy map[int64]string
	Broken map[int64]string
	// Dialog — id модалки, которую страница рендерит открытой (пустая строка —
	// все закрыты). Заполняется только вместе с Error.
	Dialog string
	// Upload — уже введённые значения формы заливки, чтобы после отказа их не
	// набирали заново. Нулевое значение — пустая форма.
	Upload uploadForm
}

// uploadForm — то, что пользователь успел выбрать в форме заливки. Файла здесь
// нет и быть не может: вернуть его в поле умеет только браузер.
type uploadForm struct{ Version, SHA256, OS, Arch string }

// platformOption — пункт выпадающего списка ОС для особых значений: пары с
// архитектурой у них нет, поэтому в KnownOS() они не входят и попадают в
// список отдельно. Значение берётся из словаря пакета, подпись — наша:
// вписать его в разметку литералом значило бы завести вторую копию словаря
// (R8-sec круг 2, N3).
type platformOption struct{ Value, Label string }

var specialPlatforms = []platformOption{
	{platform.Any, "any (not platform-specific)"},
	{platform.Universal, "darwin/universal (macOS fat binary)"},
}

// baseView fills what every authenticated page needs: who is logged in, what
// that role may do, and the CSRF token for the forms.
func (h *handlers) baseView(w http.ResponseWriter, r *http.Request) view {
	v := view{User: h.auth.CurrentUser(r), CSRF: h.ensureCSRF(w, r)}
	if v.User != nil {
		role := auth.Role(v.User.Role)
		v.Can = perms{
			UI:        role.Can(auth.PermUI),
			Version:   role.Can(auth.PermVersion),
			App:       role.Can(auth.PermApp),
			UserAdmin: role.Can(auth.PermUserAdmin),
		}
	}
	return v
}

func (h *handlers) render(w http.ResponseWriter, status int, name string, v view) {
	var buf bytes.Buffer // рендер в буфер: ошибка шаблона не портит начатый ответ
	if err := h.tpl[name].ExecuteTemplate(&buf, "layout", v); err != nil {
		h.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func (h *handlers) serverError(w http.ResponseWriter, err error) {
	log.Printf("web: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// removeErr answers a failed cleanup on disk, when the DB row is already gone.
// ErrNotDirectory означает, что имя приложения совпало с соседом в data-dir
// (файл БД, .tmp) и на диске ничего не тронуто — это 409, а не 500. Путь
// уходит только в серверный лог.
func (h *handlers) removeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, files.ErrNotDirectory) {
		log.Printf("web: %v", err)
		http.Error(w, "storage path is not an application directory, "+
			"nothing was removed from disk", http.StatusConflict)
		return
	}
	h.serverError(w, err)
}

// actor names the authenticated user for the audit log of destructive
// operations. Только имя: пароли, хеши и токены сессий не логируются.
func (h *handlers) actor(r *http.Request) string {
	if u := h.auth.CurrentUser(r); u != nil {
		return u.Username
	}
	return "?"
}

// sanitizeNext keeps redirects on-site: only relative paths starting with a
// single "/" are allowed, anything else falls back to "/".
func sanitizeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") &&
		!strings.Contains(next, "\\") {
		return next
	}
	return "/"
}

// --- login / logout ---

// loginNotices are the messages /login may show, addressed by a short code in
// the query. Фиксированный список: свободный текст из URL на странице входа —
// готовый инструмент фишинга.
var loginNotices = map[string]string{
	"password-changed": "Your password has been changed. Please log in again.",
	// Ставит скрипт загрузки, когда XHR прозрачно прошёл 303 на /login: сессия
	// истекла посреди заливки, файл не сохранён, и молча показать форму входа
	// вместо страницы приложения — значит оставить пользователя гадать (R7-sec, S2).
	"session-expired": "Your session has expired, so the upload did not go through. Please log in and repeat it.",
}

func (h *handlers) loginForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusOK, "login", view{
		CSRF:   h.ensureCSRF(w, r),
		Next:   sanitizeNext(r.URL.Query().Get("next")),
		Notice: loginNotices[r.URL.Query().Get("m")],
	})
}

func (h *handlers) loginPost(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.PostFormValue("next"))
	err := h.auth.LoginUser(w, r.PostFormValue("username"), r.PostFormValue("password"))
	if err != nil {
		h.render(w, http.StatusUnauthorized, "login", view{
			CSRF: h.ensureCSRF(w, r), Next: next,
			Error: "invalid username or password",
		})
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	h.auth.LogoutUser(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- app list ---

func (h *handlers) index(w http.ResponseWriter, r *http.Request) {
	h.renderIndex(w, r, http.StatusOK, "", "")
}

// renderIndex renders the app list, re-opening the named dialog when errMsg is
// non-empty so the failed form stays visible next to the error banner.
func (h *handlers) renderIndex(w http.ResponseWriter, r *http.Request, status int, dialog, errMsg string) {
	apps, err := h.st.ListApps()
	if err != nil {
		h.serverError(w, err)
		return
	}
	rows := make([]appRow, 0, len(apps))
	for _, a := range apps {
		vs, err := h.st.ListVersions(a.ID)
		if err != nil {
			h.serverError(w, err)
			return
		}
		latest, err := h.st.LatestVersion(a.ID)
		if err != nil {
			h.serverError(w, err)
			return
		}
		rows = append(rows, appRow{App: a, Latest: latest, VersionsCount: len(vs)})
	}
	v := h.baseView(w, r)
	v.Apps = rows
	if errMsg != "" {
		v.Error, v.Dialog = errMsg, dialog
	}
	h.render(w, status, "index", v)
}

func (h *handlers) createApp(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if err := naming.ValidateAppName(name); err != nil {
		h.renderIndex(w, r, http.StatusBadRequest, "new-app", err.Error())
		return
	}
	if _, err := h.st.CreateApp(name, desc); err != nil {
		if errors.Is(err, store.ErrExists) {
			h.renderIndex(w, r, http.StatusConflict, "new-app",
				fmt.Sprintf("application %q already exists", name))
			return
		}
		h.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/apps/"+url.PathEscape(name), http.StatusSeeOther)
}

// --- app page ---

// loadApp resolves {name} from the path; on failure it has already written
// the response and returns nil.
func (h *handlers) loadApp(w http.ResponseWriter, r *http.Request) *store.App {
	name := r.PathValue("name")
	if naming.ValidateAppName(name) != nil {
		http.NotFound(w, r)
		return nil
	}
	app, err := h.st.GetApp(name)
	if err != nil {
		h.serverError(w, err)
		return nil
	}
	if app == nil {
		http.NotFound(w, r)
		return nil
	}
	return app
}

func (h *handlers) appPage(w http.ResponseWriter, r *http.Request) {
	if app := h.loadApp(w, r); app != nil {
		h.renderApp(w, r, app, http.StatusOK, "")
	}
}

func (h *handlers) renderApp(w http.ResponseWriter, r *http.Request, app *store.App, status int, errMsg string) {
	h.renderAppIn(w, r, app, status, "upload", errMsg)
}

// renderUpload — отказ форме заливки: то же, что renderApp, но с возвратом уже
// заполненных полей, чтобы версию и платформу не набирали заново.
func (h *handlers) renderUpload(w http.ResponseWriter, r *http.Request, app *store.App, status int, form uploadForm, errMsg string) {
	h.renderAppForm(w, r, app, status, "upload", form, errMsg)
}

// platformDialog — id модалки простановки платформы у версии. Строка одна на
// шаблон и на хендлер: разъехавшись, они молча перестали бы её открывать.
func platformDialog(version string) string { return "platform-" + version }

// renderAppIn renders the app page, re-opening the named dialog when errMsg is
// non-empty so the failed form stays visible next to the error banner.
func (h *handlers) renderAppIn(w http.ResponseWriter, r *http.Request, app *store.App, status int, dialog, errMsg string) {
	h.renderAppForm(w, r, app, status, dialog, uploadForm{}, errMsg)
}

// renderAppForm is renderAppIn plus the upload form's own values.
func (h *handlers) renderAppForm(w http.ResponseWriter, r *http.Request, app *store.App, status int, dialog string, form uploadForm, errMsg string) {
	if errMsg == "" {
		dialog = ""
	}
	vs, err := h.st.ListVersions(app.ID)
	if err != nil {
		h.serverError(w, err)
		return
	}
	latest, err := h.st.LatestVersion(app.ID)
	if err != nil {
		h.serverError(w, err)
		return
	}
	rows := make([]verRow, 0, len(vs))
	for _, v := range vs {
		goos, goarch, _ := strings.Cut(v.Platform, "/")
		if v.Platform == platform.Universal {
			// Особое значение — целиком в список ОС, как any: пары «архитектура
			// universal» не существует, и половинки тут врозь не живут.
			goos, goarch = platform.Universal, ""
		}
		open := dialog == platformDialog(v.Version)
		if open {
			// Диалог открывается заново после отказа — с тем, что отправили, а
			// не с сохранённым значением: то же поведение, что у формы заливки
			// (R8-qa, замечание 4).
			goos, goarch = form.OS, form.Arch
		}
		rows = append(rows, verRow{V: v, IsLatest: latest != nil && v.ID == latest.ID,
			OS: goos, Arch: goarch, DialogOpen: open})
	}
	v := h.baseView(w, r)
	v.Error, v.App, v.Versions, v.Latest = errMsg, app, rows, latest
	v.Pinned, v.Dialog, v.Upload = app.LatestOverrideVersionID != nil, dialog, form
	v.PlatformOS, v.PlatformArch = platform.KnownOS(), platform.KnownArch()
	v.PlatformSpecial = specialPlatforms
	h.render(w, status, "app", v)
}

// loadVersion resolves {version} of app from the path; on failure it has
// already written the response and returns nil.
func (h *handlers) loadVersion(w http.ResponseWriter, r *http.Request, app *store.App) *store.Version {
	version, err := naming.ValidateVersion(r.PathValue("version"))
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	v, err := h.st.GetVersion(app.ID, version)
	if err != nil {
		h.serverError(w, err)
		return nil
	}
	if v == nil {
		http.NotFound(w, r)
		return nil
	}
	return v
}

// platformField reads the two dropdowns of a form as one canonical platform:
// пусто — не указана (при заливке определим по файлу, у существующей версии
// это сброс в «неизвестно»); platform.Any — не зависит от платформы; иначе
// пара уходит в platform.Parse, который канонизирует её и отвергает всё, чего
// нет в словаре. Текст его ошибки показывается пользователю как есть.
func platformField(get func(string) string) (string, error) {
	goos, goarch := get("platform_os"), get("platform_arch")
	if goos == "" && goarch == "" {
		return "", nil
	}
	if goos == platform.Any || goos == platform.Universal {
		return goos, nil // у особых значений архитектуры нет
	}
	return platform.Parse(goos + "/" + goarch)
}

// setVersionPlatform sets or clears the platform of a version by hand: the
// path for archives, where there is nothing in the file to detect.
func (h *handlers) setVersionPlatform(w http.ResponseWriter, r *http.Request) {
	app := h.loadApp(w, r)
	if app == nil {
		return
	}
	v := h.loadVersion(w, r, app)
	if v == nil {
		return
	}
	p, err := platformField(r.PostFormValue)
	if err != nil {
		h.renderAppForm(w, r, app, http.StatusBadRequest, platformDialog(v.Version),
			uploadForm{OS: r.PostFormValue("platform_os"), Arch: r.PostFormValue("platform_arch")},
			err.Error())
		return
	}
	// Пустая строка допустима и означает сброс: SetVersionPlatform пропускает
	// её мимо Parse (для Parse пустая строка — ошибка).
	if err := h.st.SetVersionPlatform(v.ID, p); err != nil {
		h.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/apps/"+url.PathEscape(app.Name), http.StatusSeeOther)
}

// --- upload ---

func (h *handlers) upload(w http.ResponseWriter, r *http.Request) {
	app := h.loadApp(w, r)
	if app == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		h.multipartError(w, r, app, err)
		return
	}
	// Части читаются потоково в порядке формы; в шаблоне file — последнее
	// поле, поэтому к моменту файла csrf_token/version/sha256 уже собраны.
	fields := map[string]string{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.multipartError(w, r, app, err)
			return
		}
		if part.FormName() != "file" {
			// Жёсткий потолок на текстовые части: форма шлёт три, а тело
			// ограничено только MaxUploadBytes — без лимита числа частей
			// злоумышленник раздувает карту fields до OOM.
			if len(fields) >= maxUploadFields {
				h.renderApp(w, r, app, http.StatusBadRequest, "too many form fields")
				return
			}
			b, err := io.ReadAll(io.LimitReader(part, maxFieldBytes))
			if err != nil {
				h.multipartError(w, r, app, err)
				return
			}
			fields[part.FormName()] = strings.TrimSpace(string(b))
			continue
		}
		if !csrfOK(r, fields[csrfField]) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		h.saveUpload(w, r, app, fields, part)
		return
	}
	if !csrfOK(r, fields[csrfField]) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	h.renderApp(w, r, app, http.StatusBadRequest, "no file in upload")
}

func (h *handlers) saveUpload(w http.ResponseWriter, r *http.Request, app *store.App, fields map[string]string, part *multipart.Part) {
	form := uploadForm{Version: fields["version"], SHA256: fields["sha256"],
		OS: fields["platform_os"], Arch: fields["platform_arch"]}
	version, err := naming.ValidateVersion(fields["version"])
	if err != nil {
		h.renderUpload(w, r, app, http.StatusBadRequest, form, err.Error())
		return
	}
	// Платформа разбирается до чтения тела: негодная пара не должна стоить
	// клиенту гигабайта трафика (тот же порядок, что у имени файла).
	plat, err := platformField(func(k string) string { return fields[k] })
	if err != nil {
		h.renderUpload(w, r, app, http.StatusBadRequest, form, err.Error())
		return
	}
	// Браузеры шлют basename, но на всякий случай срезаем путь любого ОС.
	filename := part.FileName()
	if i := strings.LastIndexAny(filename, `/\`); i >= 0 {
		filename = filename[i+1:]
	}
	if err := naming.ValidateFilename(filename); err != nil {
		h.renderUpload(w, r, app, http.StatusBadRequest, form, err.Error())
		return
	}
	// Ранняя проверка дубля: не гонять гигабайты, чтобы упасть на UNIQUE.
	if v, err := h.st.GetVersion(app.ID, version); err != nil {
		h.serverError(w, err)
		return
	} else if v != nil {
		h.renderUpload(w, r, app, http.StatusConflict, form,
			fmt.Sprintf("version %s already exists", version))
		return
	}
	up, err := h.fs.Prepare(app.Name, version, filename, part, fields["sha256"])
	if err != nil {
		h.uploadError(w, r, app, err)
		return
	}
	// Платформа решается по временному файлу, ДО публикации: отказ тогда не
	// создаёт ни каталога версии, ни файла в нём (R8-sec S2). Ошибка чтения —
	// то же «не опознано», но с записью в лог.
	detected, err := platform.Detect(up.Path())
	if err != nil {
		log.Printf("web: detect platform of %s/%s: %v", app.Name, version, err)
		detected = ""
	}
	switch {
	case plat == "" && detected == "":
		// У архива определять нечего, и версия без платформы не создаётся
		// вовсе: указать её потом можно, а незаметно потерять — нельзя.
		h.discardUpload(up, app.Name, version)
		h.renderUpload(w, r, app, http.StatusBadRequest, form,
			"could not tell from the file which OS and architecture it is built for "+
				"(archives carry nothing to read): pick them in the upload form, or "+
				`"any" if this file does not depend on a platform. Nothing was stored.`)
		return
	case plat == "":
		plat = detected
	case detected != "" && detected != plat:
		// Тот же вердикт, что у API (409 platform_mismatch): один класс ответа
		// на одну ошибку в обоих интерфейсах. Молчаливое расхождение метки и
		// содержимого обнаруживает не тот, кто залил, а тот, кто скачал
		// артефакт, — поэтому отказ, а не переопределение (R8-test, находка 1).
		h.discardUpload(up, app.Name, version)
		h.renderUpload(w, r, app, http.StatusConflict, form, fmt.Sprintf(
			"the file you picked is built for %s, but the form says %s; nothing was stored. "+
				"Upload the matching file, correct the platform, or leave it on "+
				`"detect automatically" and let the server read it from the file. `+
				"A detection you disagree with can be corrected on this page after the upload.",
			detected, plat))
		return
	}
	// Публикация — под замком имени приложения, с перепроверкой строки: пока
	// лилось тело, приложение могли переименовать или удалить, и файл лёг бы
	// в каталог, на который уже никто не ссылается (F10).
	if err := up.Commit(func() error { return h.stillNamed(app) }); err != nil {
		h.uploadError(w, r, app, err)
		return
	}
	v, err := h.st.CreateVersion(app.ID, version, filename, up.Size, up.SHA256)
	if err != nil {
		h.rollbackFile(app.Name, version, filename)
		h.uploadError(w, r, app, err)
		return
	}
	if err := h.st.SetVersionPlatform(v.ID, plat); err != nil {
		// Версия уже опубликована — откатывать удачную заливку из-за одной
		// колонки неправильно, а молчать нельзя: платформа осталась пустой и
		// проставляется руками на этой же странице.
		h.serverError(w, fmt.Errorf("set platform %q of %s/%s: %w", plat, app.Name, version, err))
		return
	}
	http.Redirect(w, r, "/apps/"+url.PathEscape(app.Name), http.StatusSeeOther)
}

// discardUpload removes the temp file of an upload refused before publication.
// Неудача уборки — только в лог: клиент свой отказ уже получил, но мусор в
// {Root}/.tmp никто больше не подберёт, и оператор обязан его увидеть.
func (h *handlers) discardUpload(up *files.Upload, app, version string) {
	if err := up.Discard(); err != nil {
		log.Printf("web: discard of temp upload %s/%s failed: %v", app, version, err)
	}
}

// rollbackFile removes a file that was published but whose version row is not
// going to exist. A failed cleanup only goes to the log: the client already has
// its refusal, but the leftover file would block a retry with 409, so the
// operator must see it.
func (h *handlers) rollbackFile(app, version, filename string) {
	if err := h.fs.Remove(app, version, filename); err != nil {
		log.Printf("web: rollback of %s/%s/%s failed: %v", app, version, filename, err)
	}
}

// errAppMoved reports that the app the upload started against no longer holds
// its name — renamed or deleted while the body was streaming.
var errAppMoved = errors.New("app was renamed or removed during upload")

// stillNamed re-reads the app row by the name the upload targeted; it runs
// under the app lock taken by Upload.Commit, so a rename is either entirely
// before it (and this fails) or entirely after it (and moves the published
// file along with the rest of the directory).
func (h *handlers) stillNamed(app *store.App) error {
	cur, err := h.st.GetApp(app.Name)
	if err != nil {
		return err
	}
	if cur == nil || cur.ID != app.ID {
		return errAppMoved
	}
	return nil
}

// multipartError answers a request body that could not be read: malformed
// parts, a header the MIME parser refuses, a premature EOF. Это негодный
// ЗАПРОС, а не сбой сервера, поэтому 4xx — и в UI, и в API одна и та же
// ошибка обязана попадать в один класс кодов (R7-qa, находка 3). Текст
// разбора относится к присланному телу и внутренних подробностей не несёт.
// Единственное исключение — превышение лимита: у него свой 413.
func (h *handlers) multipartError(w http.ResponseWriter, r *http.Request, app *store.App, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		h.renderApp(w, r, app, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file is too large (limit %d bytes)", h.cfg.MaxUploadBytes))
		return
	}
	h.renderApp(w, r, app, http.StatusBadRequest, "invalid upload request: "+err.Error())
}

// uploadError renders a human-readable upload failure on the app page.
func (h *handlers) uploadError(w http.ResponseWriter, r *http.Request, app *store.App, err error) {
	var maxErr *http.MaxBytesError
	switch {
	case errors.Is(err, files.ErrHashMismatch):
		h.renderApp(w, r, app, http.StatusUnprocessableEntity,
			"SHA-256 mismatch: the file was rejected and not stored")
	case errors.Is(err, errAppMoved):
		// Ничего не опубликовано, временный файл убран: конфликт, не сбой.
		h.renderApp(w, r, app, http.StatusConflict,
			"this application was renamed or removed while the file was uploading, nothing was stored")
	case errors.Is(err, store.ErrExists), errors.Is(err, files.ErrFileExists):
		// files.ErrFileExists — проигравший гонки загрузок: файл победителя
		// не тронут, это тот же логический конфликт, что и дубль в БД.
		h.renderApp(w, r, app, http.StatusConflict, "this version already exists")
	case errors.Is(err, files.ErrNotDirectory):
		// Имя приложения занято соседом в data-dir (файл БД, .tmp): на диске
		// ничего не создано — это конфликт, не сбой. Путь — только в лог.
		log.Printf("web: upload to %s failed: %v", app.Name, err)
		h.renderApp(w, r, app, http.StatusConflict,
			"storage path is not an application directory, nothing was written to disk")
	case errors.As(err, &maxErr):
		h.renderApp(w, r, app, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file is too large (limit %d bytes)", h.cfg.MaxUploadBytes))
	default:
		// Нераспознанная ошибка публикации — сбой сервера, а не клиента:
		// 500 и запись в лог, как в API (api.uploadErr → internalErr).
		// Прежние 400 «upload failed» прятали поломку диска от мониторинга
		// под видом ошибки пользователя, и одна и та же ошибка ФС давала
		// 400 в UI против 500 в API (R7-qa, находка 3). Текст ошибки (пути
		// ФС, SQLite) по-прежнему уходит только в лог.
		h.serverError(w, fmt.Errorf("upload to %s failed: %w", app.Name, err))
	}
}

// --- latest management ---

func (h *handlers) setLatest(w http.ResponseWriter, r *http.Request) {
	app := h.loadApp(w, r)
	if app == nil {
		return
	}
	if want := r.PostFormValue("version"); want == "auto" {
		if err := h.st.SetLatestOverride(app.ID, nil); err != nil {
			h.serverError(w, err)
			return
		}
	} else {
		canon, err := naming.ValidateVersion(want)
		if err != nil {
			h.renderApp(w, r, app, http.StatusBadRequest, err.Error())
			return
		}
		v, err := h.st.GetVersion(app.ID, canon)
		if err != nil {
			h.serverError(w, err)
			return
		}
		if v == nil {
			h.renderApp(w, r, app, http.StatusBadRequest,
				fmt.Sprintf("version %q not found", want))
			return
		}
		if err := h.st.SetLatestOverride(app.ID, &v.ID); err != nil {
			h.serverError(w, err)
			return
		}
	}
	http.Redirect(w, r, "/apps/"+url.PathEscape(app.Name), http.StatusSeeOther)
}

// --- edit / delete ---

// editApp renames the app and replaces its description. Order matters: the DB
// row goes first (its UNIQUE catches a taken name), the directory follows. A
// failed directory rename is compensated by renaming the row back, otherwise
// the DB would point at a directory that is not there.
func (h *handlers) editApp(w http.ResponseWriter, r *http.Request) {
	app := h.loadApp(w, r)
	if app == nil {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if err := naming.ValidateAppName(name); err != nil {
		h.renderAppIn(w, r, app, http.StatusBadRequest, "edit", err.Error())
		return
	}
	if err := h.st.UpdateApp(app.ID, name, desc); err != nil {
		if errors.Is(err, store.ErrExists) {
			h.renderAppIn(w, r, app, http.StatusConflict, "edit",
				fmt.Sprintf("application %q already exists", name))
			return
		}
		h.serverError(w, err)
		return
	}
	if err := h.fs.RenameApp(app.Name, name); err != nil {
		log.Printf("web: rename %s -> %s on disk failed: %v", app.Name, name, err)
		if rbErr := h.st.UpdateApp(app.ID, app.Name, app.Description); rbErr != nil {
			// Компенсация не удалась: строка указывает на старый каталог,
			// которого нет. Чинится вручную, поэтому пишем громко.
			log.Printf("web: reverting %s to %s failed: %v", name, app.Name, rbErr)
		}
		// Каталог-приёмник занят (осиротевший каталог от прежнего приложения):
		// перенос отказан, ничего не перезаписано — 409, как и в api.updateApp.
		if errors.Is(err, files.ErrFileExists) {
			h.renderAppIn(w, r, app, http.StatusConflict, "edit",
				fmt.Sprintf("a storage directory named %q already exists — nothing was renamed on disk", name))
			return
		}
		// Имя приложения совпало с соседом в data-dir (файл БД, .tmp): на
		// диске ничего не двигалось, имя откачено — это конфликт, не сбой.
		if errors.Is(err, files.ErrNotDirectory) {
			h.renderAppIn(w, r, app, http.StatusConflict, "edit",
				"storage path is not an application directory, nothing was renamed on disk")
			return
		}
		h.renderAppIn(w, r, app, http.StatusInternalServerError, "edit",
			"could not rename files on disk, the application was left unchanged")
		return
	}
	if name != app.Name {
		log.Printf("web: user %q renamed app %q to %q", h.actor(r), app.Name, name)
	}
	http.Redirect(w, r, "/apps/"+url.PathEscape(name), http.StatusSeeOther)
}

// deleteApp drops the app with every version and file it owns. The user must
// retype the name: the operation is irreversible and hits more than one row.
func (h *handlers) deleteApp(w http.ResponseWriter, r *http.Request) {
	app := h.loadApp(w, r)
	if app == nil {
		return
	}
	if r.PostFormValue("confirm") != app.Name {
		h.renderAppIn(w, r, app, http.StatusBadRequest, "delete",
			fmt.Sprintf("type %q exactly to confirm deletion — nothing was deleted", app.Name))
		return
	}
	// БД первой: осиротевший каталог безвреден, строка без файлов — нет.
	if err := h.st.DeleteApp(app.ID); err != nil {
		h.serverError(w, err)
		return
	}
	if err := h.fs.RemoveApp(app.Name); err != nil {
		log.Printf("web: user %q deleted app %q: row removed, disk cleanup failed", h.actor(r), app.Name)
		h.removeErr(w, fmt.Errorf("remove files of app %s: %w", app.Name, err))
		return
	}
	log.Printf("web: user %q deleted app %q", h.actor(r), app.Name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handlers) deleteVersion(w http.ResponseWriter, r *http.Request) {
	app := h.loadApp(w, r)
	if app == nil {
		return
	}
	v := h.loadVersion(w, r, app)
	if v == nil {
		return
	}
	version := v.Version
	if err := h.st.DeleteVersion(v.ID); err != nil {
		h.serverError(w, err)
		return
	}
	if err := h.fs.RemoveVersion(app.Name, version); err != nil {
		log.Printf("web: user %q deleted version %s/%s: row removed, disk cleanup failed",
			h.actor(r), app.Name, version)
		h.removeErr(w, fmt.Errorf("remove files of %s/%s: %w", app.Name, version, err))
		return
	}
	log.Printf("web: user %q deleted version %s/%s", h.actor(r), app.Name, version)
	http.Redirect(w, r, "/apps/"+url.PathEscape(app.Name), http.StatusSeeOther)
}
