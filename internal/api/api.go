// Package api implements the JSON API under /api/ and binary downloads under
// /download/, both protected by HTTP Basic Auth.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/files"
	"apprepo/internal/naming"
	"apprepo/internal/platform"
	"apprepo/internal/store"
)

// maxJSONBody bounds JSON request bodies; metadata is tiny.
const maxJSONBody = 1 << 20

type server struct {
	st   *store.Store
	fs   *files.Storage
	auth *auth.Auth // CurrentUser: журнал деструктивных операций и /api/me
	cfg  config.Config
}

// Register mounts the API and download routes on mux behind Basic Auth.
func Register(mux *http.ServeMux, st *store.Store, fs *files.Storage, a *auth.Auth, cfg config.Config) {
	s := &server{st: st, fs: fs, auth: a, cfg: cfg}

	api := http.NewServeMux()
	// handle вешает на маршрут право из матрицы ролей. Require обязан идти
	// после RequireBasic — тот стоит ниже на всём /api/, так что пользователь
	// в контексте здесь уже есть.
	handle := func(pattern string, p auth.Permission, h http.HandlerFunc) {
		api.Handle(pattern, a.Require(p, h))
	}
	handle("GET /api/apps", auth.PermRead, s.listApps)
	handle("POST /api/apps", auth.PermApp, s.createApp)
	handle("GET /api/apps/{name}", auth.PermRead, s.getApp)
	handle("PATCH /api/apps/{name}", auth.PermApp, s.updateApp)
	handle("DELETE /api/apps/{name}", auth.PermApp, s.deleteApp)
	handle("GET /api/apps/{name}/versions", auth.PermRead, s.listVersions)
	handle("GET /api/apps/{name}/versions/{version}", auth.PermRead, s.getVersion)
	handle("PUT /api/apps/{name}/versions/{version}", auth.PermVersion, s.putVersion)
	// Простановка платформы руками — операция над версией, право то же, что у
	// заливки и удаления: кто выпускает версию, тот и правит её метку.
	handle("PATCH /api/apps/{name}/versions/{version}", auth.PermVersion, s.updateVersion)
	handle("DELETE /api/apps/{name}/versions/{version}", auth.PermVersion, s.deleteVersion)
	handle("GET /api/apps/{name}/latest", auth.PermRead, s.getLatest)
	// Закрепление latest — про релиз версии, а не про карточку приложения: кто
	// заливает и удаляет версии, тот и двигает latest (удалением версии он его
	// и так двигает).
	handle("POST /api/apps/{name}/latest", auth.PermVersion, s.setLatest)

	handle("GET /api/users", auth.PermUserAdmin, s.listUsers)
	handle("POST /api/users", auth.PermUserAdmin, s.createUser)
	handle("PATCH /api/users/{username}", auth.PermUserAdmin, s.updateUser)
	handle("POST /api/users/{username}/password", auth.PermUserAdmin, s.setUserPassword)
	handle("DELETE /api/users/{username}", auth.PermUserAdmin, s.deleteUser)

	// Своя учётка — без права: узнать себя и сменить свой пароль должна уметь
	// любая роль. Иначе deployer, которого в UI не пускают вовсе, не сменит
	// пароль ниоткуда.
	api.HandleFunc("GET /api/me", s.getMe)
	api.HandleFunc("POST /api/me/password", s.changeMyPassword)

	// Catch-all: неизвестный путь или метод внутри /api/ отвечает JSON, а не
	// текстовым 404/405 от ServeMux (контракт: все ошибки API — JSON).
	handle("/api/", auth.PermRead, func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no such API route")
	})
	mux.Handle("/api/", json401(a.RequireBasic(api)))

	// Для /download текстовый 401 от middleware допустим по плану.
	mux.Handle("GET /download/{name}/{version}",
		a.RequireBasic(a.Require(auth.PermRead, http.HandlerFunc(s.download))))
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// notJSON reports whether a non-empty request body must be refused because its
// Content-Type is not application/json, answering 415 itself when it must.
//
// Зачем: /api/ аутентифицируется только Basic Auth — сессионной куки здесь нет,
// значит SameSite не участвует и своей защиты от CSRF у API нет. Браузер, у
// которого в кэше лежат Basic-креды к этому origin (их кладёт туда один клик по
// ссылке /download из UI), приложит их к кросс-сайтовому запросу со стороннего
// сайта. Единственный барьер — preflight: запрос, который его не требует,
// уходит молча, а ответ атакующему и не нужен, ему нужен эффект.
//
// Поэтому список разрешённого — белый и ровно из одного значения. Без
// preflight кросс-сайтовый запрос может иметь только Content-Type из
// CORS-safelist: отсутствующий, text/plain, application/x-www-form-urlencoded,
// multipart/form-data. Все четыре доставляют произвольное тело — `fetch` и
// `navigator.sendBeacon` шлют любые байты (у `Blob` с пустым `type` заголовка
// не будет вовсе), так что «валидным JSON такой запрос не станет» верно
// только для настоящей HTML-<form> и денилист по типам класс не закрывает
// (F12 → R6-sec круг 2). application/json в safelist не входит: запрос с ним
// требует preflight, а preflight сервис не проходит.
//
// Отсутствующий и неразбираемый заголовок — тоже отказ: защитный рубеж обязан
// падать закрыто. Исключение одно — пустое тело: PATCH без полей («ничего не
// менять») легален и Content-Type ему не нужен; доставить им нечего.
func notJSON(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength == 0 { // тела нет; -1 (длина неизвестна) сюда не попадает
		return false
	}
	// ParseMediaType уже отбрасывает параметры (charset) и приводит тип к
	// нижнему регистру; EqualFold — на случай смены её поведения.
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"request body must be sent with Content-Type: application/json")
		return true
	}
	return false
}

// internalErr logs the real error server-side and answers with a fixed body:
// тексты внутренних ошибок (пути ФС, SQLite) клиенту не уходят.
func internalErr(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("api: %s %s: %v", r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal", "internal error")
}

// removeErr answers a failed cleanup on disk. ErrNotDirectory means the app
// name collided with a neighbour in the data dir (the SQLite file, .tmp) and
// nothing was touched — 409, same code as a rename onto an occupied path.
// Путь попадает только в серверный лог, клиенту — фиксированный текст.
func removeErr(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, files.ErrNotDirectory) {
		log.Printf("api: %s %s: %v", r.Method, r.URL.Path, err)
		writeErr(w, http.StatusConflict, "already_exists",
			"storage path is not an application directory, nothing was removed from disk")
		return
	}
	internalErr(w, r, err)
}

// actor names the authenticated user for the audit log of destructive
// operations. Только имя: пароли, хеши и токены не логируются.
func (s *server) actor(r *http.Request) string {
	if u := s.auth.CurrentUser(r); u != nil {
		return u.Username
	}
	return "?"
}

// json401 wraps a handler chain so that a 401 written by the auth middleware
// (whose body format this package does not control) is emitted as the
// contract JSON error object. The WWW-Authenticate header set by the
// middleware is preserved.
func json401(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&auth401Writer{ResponseWriter: w}, r)
	})
}

type auth401Writer struct {
	http.ResponseWriter
	replaced bool
}

func (w *auth401Writer) WriteHeader(code int) {
	if code == http.StatusUnauthorized && !w.replaced {
		w.replaced = true
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Del("Content-Length")
		w.ResponseWriter.WriteHeader(code)
		json.NewEncoder(w.ResponseWriter).Encode(map[string]string{
			"error": "unauthorized", "message": "authentication required",
		})
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write drops the middleware's own 401 body once it has been replaced.
func (w *auth401Writer) Write(b []byte) (int, error) {
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// --- response shapes (контракт «Объект версии») ---

type versionJSON struct {
	Version     string `json:"version"`
	Filename    string `json:"filename"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	Platform    string `json:"platform"` // "os/arch", "any" или "" — неизвестна
	CreatedAt   string `json:"created_at"`
	DownloadURL string `json:"download_url"`
	IsLatest    bool   `json:"is_latest"`
}

type appJSON struct {
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	VersionsCount int          `json:"versions_count"`
	Latest        *versionJSON `json:"latest"`
	CreatedAt     string       `json:"created_at"`
}

func (s *server) versionObj(appName string, v, latest *store.Version) *versionJSON {
	return &versionJSON{
		Version:     v.Version,
		Filename:    v.Filename,
		SizeBytes:   v.SizeBytes,
		SHA256:      v.SHA256,
		Platform:    v.Platform,
		CreatedAt:   v.CreatedAt.UTC().Format(time.RFC3339),
		DownloadURL: strings.TrimSuffix(s.cfg.BaseURL, "/") + "/download/" + appName + "/" + v.Version,
		IsLatest:    latest != nil && latest.ID == v.ID,
	}
}

// appInfo loads an app's versions and resolved latest and builds its JSON.
func (s *server) appInfo(a *store.App) (appJSON, []*versionJSON, error) {
	vs, err := s.st.ListVersions(a.ID)
	if err != nil {
		return appJSON{}, nil, err
	}
	latest, err := s.st.LatestVersion(a.ID)
	if err != nil {
		return appJSON{}, nil, err
	}
	objs := make([]*versionJSON, len(vs))
	for i, v := range vs {
		objs[i] = s.versionObj(a.Name, v, latest)
	}
	aj := appJSON{
		Name:          a.Name,
		Description:   a.Description,
		VersionsCount: len(vs),
		CreatedAt:     a.CreatedAt.UTC().Format(time.RFC3339),
	}
	if latest != nil {
		aj.Latest = s.versionObj(a.Name, latest, latest)
	}
	return aj, objs, nil
}

// mustApp resolves {name} to an app or writes a 404 and returns nil. Имя из
// URL проверяется до похода в БД (как web.loadApp): невалидного имени в
// таблице быть не может, а на этом инварианте держится files.RemoveApp.
func (s *server) mustApp(w http.ResponseWriter, r *http.Request) *store.App {
	name := r.PathValue("name")
	if naming.ValidateAppName(name) != nil {
		writeErr(w, http.StatusNotFound, "not_found", "app not found")
		return nil
	}
	a, err := s.st.GetApp(name)
	if err != nil {
		internalErr(w, r, err)
		return nil
	}
	if a == nil {
		writeErr(w, http.StatusNotFound, "not_found", "app not found")
		return nil
	}
	return a
}

// mustVersion resolves {version} within a or writes 400/404 and returns nil.
func (s *server) mustVersion(w http.ResponseWriter, r *http.Request, a *store.App) *store.Version {
	canon, err := naming.ValidateVersion(r.PathValue("version"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_version", err.Error())
		return nil
	}
	v, err := s.st.GetVersion(a.ID, canon)
	if err != nil {
		internalErr(w, r, err)
		return nil
	}
	if v == nil {
		writeErr(w, http.StatusNotFound, "not_found", "version not found")
		return nil
	}
	return v
}

// writeAppDetail responds with the app object plus its versions; GET и PATCH
// приложения отдают один и тот же формат.
func (s *server) writeAppDetail(w http.ResponseWriter, r *http.Request, a *store.App) {
	aj, versions, err := s.appInfo(a)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		appJSON
		Versions []*versionJSON `json:"versions"`
	}{aj, versions})
}

// --- /api/apps handlers ---

func (s *server) listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.st.ListApps()
	if err != nil {
		internalErr(w, r, err)
		return
	}
	out := make([]appJSON, 0, len(apps))
	for _, a := range apps {
		aj, _, err := s.appInfo(a)
		if err != nil {
			internalErr(w, r, err)
			return
		}
		out = append(out, aj)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createApp(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := naming.ValidateAppName(in.Name); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_name", err.Error())
		return
	}
	a, err := s.st.CreateApp(in.Name, in.Description)
	if errors.Is(err, store.ErrExists) {
		writeErr(w, http.StatusConflict, "already_exists", "app already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, appJSON{
		Name:        a.Name,
		Description: a.Description,
		CreatedAt:   a.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func (s *server) getApp(w http.ResponseWriter, r *http.Request) {
	if a := s.mustApp(w, r); a != nil {
		s.writeAppDetail(w, r, a)
	}
}

// updateApp renames the app and/or replaces its description. Both fields are
// optional: a body without them (or no body at all) changes nothing.
//
// Порядок обязателен: сначала БД (UNIQUE на apps.name — единственное, что
// сериализует одновременные переименования), потом каталог. Если каталог
// переименовать не удалось, откатываем строку обратно: строка, указывающая на
// несуществующий каталог, хуже осиротевшего каталога.
func (s *server) updateApp(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	var in struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !decodeJSON(w, r, &in) { // пустое тело = нечего менять, decodeJSON его пропускает
		return
	}
	name, desc := a.Name, a.Description
	if in.Name != nil {
		name = *in.Name
	}
	if in.Description != nil {
		desc = *in.Description
	}
	if name != a.Name || desc != a.Description {
		if err := naming.ValidateAppName(name); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_name", err.Error())
			return
		}
		if err := s.st.UpdateApp(a.ID, name, desc); err != nil {
			if errors.Is(err, store.ErrExists) {
				writeErr(w, http.StatusConflict, "already_exists", "app already exists")
				return
			}
			internalErr(w, r, err)
			return
		}
		if err := s.fs.RenameApp(a.Name, name); err != nil {
			if rbErr := s.st.UpdateApp(a.ID, a.Name, a.Description); rbErr != nil {
				log.Printf("api: rollback rename %q -> %q failed: %v", name, a.Name, rbErr)
			}
			if errors.Is(err, files.ErrFileExists) {
				writeErr(w, http.StatusConflict, "already_exists", "app directory already exists")
				return
			}
			// Имя приложения совпало с соседом в data-dir (файл БД, .tmp):
			// на диске ничего не двигалось, имя в БД откачено — 409, как и
			// у занятого приёмника. Путь — только в серверный лог.
			if errors.Is(err, files.ErrNotDirectory) {
				log.Printf("api: %s %s: %v", r.Method, r.URL.Path, err)
				writeErr(w, http.StatusConflict, "already_exists",
					"storage path is not an application directory, nothing was renamed on disk")
				return
			}
			internalErr(w, r, err)
			return
		}
		if name != a.Name {
			log.Printf("api: user %q renamed app %q to %q", s.actor(r), a.Name, name)
		}
		a.Name, a.Description = name, desc
	}
	s.writeAppDetail(w, r, a)
}

// deleteApp removes the app with all its versions, then its directory.
// Сначала БД, потом диск; ошибку удаления с диска не глушим — 500, иначе
// клиент решит, что файлы исчезли, а они остались.
func (s *server) deleteApp(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	if err := s.st.DeleteApp(a.ID); err != nil {
		internalErr(w, r, err)
		return
	}
	if err := s.fs.RemoveApp(a.Name); err != nil {
		log.Printf("api: user %q deleted app %q: row removed, disk cleanup failed", s.actor(r), a.Name)
		removeErr(w, r, err)
		return
	}
	log.Printf("api: user %q deleted app %q", s.actor(r), a.Name)
	w.WriteHeader(http.StatusNoContent)
}

// deleteVersion removes one version and its directory. Снятие latest-override
// делает FK (ON DELETE SET NULL), latest пересчитывается на лету.
func (s *server) deleteVersion(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	v := s.mustVersion(w, r, a)
	if v == nil {
		return
	}
	if err := s.st.DeleteVersion(v.ID); err != nil {
		internalErr(w, r, err)
		return
	}
	if err := s.fs.RemoveVersion(a.Name, v.Version); err != nil {
		log.Printf("api: user %q deleted version %s/%s: row removed, disk cleanup failed",
			s.actor(r), a.Name, v.Version)
		removeErr(w, r, err)
		return
	}
	log.Printf("api: user %q deleted version %s/%s", s.actor(r), a.Name, v.Version)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listVersions(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	_, versions, err := s.appInfo(a)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

func (s *server) getVersion(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	v := s.mustVersion(w, r, a)
	if v == nil {
		return
	}
	latest, err := s.st.LatestVersion(a.ID)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.versionObj(a.Name, v, latest))
}

func (s *server) getLatest(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	latest, err := s.st.LatestVersion(a.ID)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	if latest == nil {
		writeErr(w, http.StatusNotFound, "not_found", "app has no versions")
		return
	}
	writeJSON(w, http.StatusOK, s.versionObj(a.Name, latest, latest))
}

// setLatest pins latest to a concrete version or, with "auto", clears the pin.
// Responds with the resolved latest version object (null when no versions).
func (s *server) setLatest(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Version == "auto" {
		if err := s.st.SetLatestOverride(a.ID, nil); err != nil {
			internalErr(w, r, err)
			return
		}
	} else {
		canon, err := naming.ValidateVersion(in.Version)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_version", err.Error())
			return
		}
		v, err := s.st.GetVersion(a.ID, canon)
		if err != nil {
			internalErr(w, r, err)
			return
		}
		if v == nil {
			writeErr(w, http.StatusNotFound, "not_found", "version not found")
			return
		}
		if err := s.st.SetLatestOverride(a.ID, &v.ID); err != nil {
			internalErr(w, r, err)
			return
		}
	}
	latest, err := s.st.LatestVersion(a.ID)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	if latest == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, s.versionObj(a.Name, latest, latest))
}

// putVersion uploads a binary: raw request body, optional X-Checksum-Sha256
// verification, required ?filename=, optional ?platform=.
func (s *server) putVersion(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	canon, err := naming.ValidateVersion(r.PathValue("version"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_version", err.Error())
		return
	}
	// Отсутствующее и пустое имя — отдельный код от негодного: клиент, который
	// параметр не шлёт (до T23 работал на дефолте), и клиент, который шлёт
	// мусор, чинятся по-разному. Текст пишется в расчёте на лог CI: почему
	// отказ, как выглядит правильный запрос, что было раньше.
	//
	// TrimSpace до проверки: `?filename=$ARTIFACT` с незаданной переменной даёт
	// не пустую строку, а пробелы, и без обрезки это 201 с непригодным именем
	// файла вместо внятного отказа (R7-test, находка 1). Пробелы внутри имени
	// при этом остаются законными.
	filename := strings.TrimSpace(r.URL.Query().Get("filename"))
	if filename == "" {
		writeErr(w, http.StatusBadRequest, "filename_required", fmt.Sprintf(
			"the ?filename= query parameter is required and must not be empty; "+
				"it used to default to %q, and a default without an extension makes an "+
				"uploaded archive download as a file the system cannot recognise. "+
				"Name the file exactly as it should be served, extension included, e.g.: "+
				`curl -u $CRED -X PUT "$BASE/api/apps/%s/versions/%s?filename=%s-%s.tar.gz" `+
				"--data-binary @%s-%s.tar.gz",
			a.Name+"-"+canon,
			a.Name, canon, a.Name, canon, a.Name, canon))
		return
	}
	if err := naming.ValidateFilename(filename); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_filename", err.Error())
		return
	}
	// Платформа разбирается здесь, вместе с остальной валидацией, а не после
	// заливки: мусор в параметре обязан стоить клиенту ноль байтов тела.
	// Пустое значение — то же, что отсутствие параметра: `?platform=$VAR` с
	// незаданной переменной уедет в автоопределение, а не в отказ по мусору
	// (для голого бинарника это 201, для архива — внятный platform_required).
	wantPlatform := r.URL.Query().Get("platform")
	if strings.TrimSpace(wantPlatform) != "" {
		wantPlatform, err = platform.Parse(wantPlatform)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_platform", err.Error())
			return
		}
	} else {
		wantPlatform = ""
	}
	// Ранняя проверка дубля: не гонять байты, если версия уже есть.
	if existing, err := s.st.GetVersion(a.ID, canon); err != nil {
		internalErr(w, r, err)
		return
	} else if existing != nil {
		writeErr(w, http.StatusConflict, "already_exists", "version already exists")
		return
	}
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	up, err := s.fs.Prepare(a.Name, canon, filename, body, r.Header.Get("X-Checksum-Sha256"))
	if err != nil {
		s.uploadErr(w, r, err)
		return
	}
	// Платформа решается по временному файлу, ДО публикации: отказ тогда не
	// создаёт ни каталога версии, ни файла в нём, а окно между Commit и
	// CreateVersion не растягивается на время разбора — на 200 MiB оно
	// доходило до секунд, и удаление приложения внутри него давало 500 с
	// FOREIGN KEY constraint failed (R8-sec S2).
	plat, ok := s.resolvePlatform(w, r, a, canon, filename, wantPlatform, up.Path())
	if !ok {
		if err := up.Discard(); err != nil {
			log.Printf("api: %s %s: discard of temp upload failed: %v", r.Method, r.URL.Path, err)
		}
		return
	}
	// Публикация — под замком имени приложения, с перепроверкой строки: пока
	// лилось тело, приложение могли переименовать или удалить, и файл лёг бы
	// в каталог, на который уже никто не ссылается (F10).
	if err := up.Commit(func() error { return s.stillNamed(a) }); err != nil {
		s.uploadErr(w, r, err)
		return
	}
	v, err := s.st.CreateVersion(a.ID, canon, filename, up.Size, up.SHA256)
	if err != nil {
		s.rollbackFile(r, a.Name, canon, filename) // строка в БД не появилась
		if errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "already_exists", "version already exists")
			return
		}
		internalErr(w, r, err)
		return
	}
	if plat != "" {
		if err := s.st.SetVersionPlatform(v.ID, plat); err != nil {
			// Значение уже прошло Parse (или пришло из Detect каноничным), так
			// что это сбой БД, а не пользовательский ввод. Версия остаётся —
			// платформу можно доставить через PATCH.
			internalErr(w, r, err)
			return
		}
		v.Platform = plat
	}
	latest, err := s.st.LatestVersion(a.ID)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.versionObj(a.Name, v, latest))
}

// rollbackFile removes a file that was published but whose version row is not
// going to exist. Неудача уборки уходит в лог, как в web.rollbackFile: клиент
// свой отказ уже получил, но оставшийся файл потом даст 409 на честную
// повторную заливку той же версии, и оператор обязан это увидеть.
func (s *server) rollbackFile(r *http.Request, app, version, filename string) {
	if err := s.fs.Remove(app, version, filename); err != nil {
		log.Printf("api: %s %s: rollback of %s/%s/%s failed: %v",
			r.Method, r.URL.Path, app, version, filename, err)
	}
}

// resolvePlatform decides the platform of the file waiting at tmp (the
// streamed body, not yet published) and answers the request itself when it
// refuses (the caller then discards the upload).
//
// Ветки ровно три. Параметр не передан — берём определённое по файлу; не
// определилось (архив, скрипт, чужая архитектура) — отказ с готовой строкой
// curl: угадывать здесь нечего, а версия без платформы, залитая молча, потом
// не находится в фильтрах и никто её не чинит.
//
// Параметр передан и с содержимым не спорит (или содержимое не опознано) —
// верим ему: `any` на jar определить нельзя в принципе.
//
// Параметр передан и содержимому противоречит — 409 с обоими значениями:
// молчаливое расхождение метки и файла хуже явной ошибки, и `linux/amd64`,
// уехавший в артефакт с windows-бинарём внутри, обнаружится у того, кто его
// скачает. Если определение всё же ошиблось — версия заливается без параметра
// и правится PATCH'ем, это осознанное действие, а не опечатка в CI.
//
// Ошибка самого Detect (файл не читается, разборщик паникнул на враждебном
// заголовке) — не повод отказать в заливке: она равнозначна «не опознано», но
// уходит в лог, потому что в норме её быть не должно.
func (s *server) resolvePlatform(w http.ResponseWriter, r *http.Request, a *store.App, version, filename, want, tmp string) (string, bool) {
	detected, err := platform.Detect(tmp)
	if err != nil {
		log.Printf("api: %s %s: detect platform: %v", r.Method, r.URL.Path, err)
	}
	switch {
	case want == "" && detected == "":
		writeErr(w, http.StatusBadRequest, "platform_required", fmt.Sprintf(
			"the platform of the uploaded file could not be detected and no ?platform= was given; "+
				"nothing was stored. A bare executable (ELF, Mach-O, PE) is recognised automatically, "+
				"an archive is not — name its platform explicitly, or use %q when the file does not "+
				"depend on OS and architecture (a jar, a bundle of scripts). Accepted: %q or %q, or os/arch "+
				"where os is one of %s and arch is one of %s. For example: "+
				`curl -u $CRED -X PUT "$BASE/api/apps/%s/versions/%s?filename=%s&platform=linux/amd64" `+
				"--data-binary @%s",
			platform.Any, platform.Any, platform.Universal,
			strings.Join(platform.KnownOS(), ", "), strings.Join(platform.KnownArch(), ", "),
			a.Name, version, filename, filename))
		return "", false
	case want == "":
		return detected, true
	case detected != "" && detected != want:
		writeErr(w, http.StatusConflict, "platform_mismatch", fmt.Sprintf(
			"the uploaded file is built for %s, but ?platform=%s was given; nothing was stored. "+
				"Upload the matching file, correct the parameter, or omit it altogether and let the "+
				"server take the platform from the file; a detection you disagree with can be "+
				"overridden afterwards with PATCH /api/apps/%s/versions/%s {\"platform\":%q}.",
			detected, want, a.Name, version, want))
		return "", false
	}
	return want, true
}

// updateVersion sets or clears the version's platform by hand: the way out for
// an archive, whose format carries no platform, and for a detection that went
// wrong. An empty string resets it to "unknown"; a body without the field
// changes nothing (as in updateApp).
func (s *server) updateVersion(w http.ResponseWriter, r *http.Request) {
	a := s.mustApp(w, r)
	if a == nil {
		return
	}
	v := s.mustVersion(w, r, a)
	if v == nil {
		return
	}
	var in struct {
		Platform *string `json:"platform"`
	}
	if !decodeJSON(w, r, &in) { // рубеж Content-Type — внутри decodeJSON
		return
	}
	if in.Platform != nil {
		p := ""
		// Пустое значение (и строка из пробелов, которой оборачивается
		// незаданная переменная) — сброс в «неизвестно», а не отказ: Parse
		// пустую строку не принимает, сброс идёт мимо неё.
		if strings.TrimSpace(*in.Platform) != "" {
			canon, err := platform.Parse(*in.Platform)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid_platform", err.Error())
				return
			}
			p = canon
		}
		if err := s.st.SetVersionPlatform(v.ID, p); err != nil {
			internalErr(w, r, err)
			return
		}
		v.Platform = p
	}
	latest, err := s.st.LatestVersion(a.ID)
	if err != nil {
		internalErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.versionObj(a.Name, v, latest))
}

// errAppMoved reports that the app the upload started against no longer holds
// its name — renamed or deleted while the body was streaming.
var errAppMoved = errors.New("app was renamed or removed during upload")

// stillNamed re-reads the app row by the name the upload targeted; it runs
// under the app lock taken by Upload.Commit, so a rename is either entirely
// before it (and this fails) or entirely after it (and moves the published
// file along with the rest of the directory).
func (s *server) stillNamed(a *store.App) error {
	cur, err := s.st.GetApp(a.Name)
	if err != nil {
		return err
	}
	if cur == nil || cur.ID != a.ID {
		return errAppMoved
	}
	return nil
}

// uploadErr maps a failed Prepare/Commit to the contract error object.
func (s *server) uploadErr(w http.ResponseWriter, r *http.Request, err error) {
	var maxErr *http.MaxBytesError
	switch {
	case errors.Is(err, files.ErrHashMismatch):
		writeErr(w, http.StatusUnprocessableEntity, "hash_mismatch", "sha256 mismatch")
	case errors.Is(err, files.ErrFileExists):
		// Гонка двух загрузок одной версии: проигравший не тронул файл
		// победителя, ему логический конфликт, а не 500 с путём ФС.
		writeErr(w, http.StatusConflict, "already_exists", "version already exists")
	case errors.Is(err, errAppMoved):
		// Ничего не опубликовано, временный файл убран: конфликт, не сбой.
		writeErr(w, http.StatusConflict, "already_exists",
			"app was renamed or removed while the upload was in flight, nothing was written to disk")
	case errors.Is(err, files.ErrNotDirectory):
		// Имя приложения занято соседом в data-dir (файл БД, .tmp): на
		// диске ничего не создано — 409, как у удаления и переименования,
		// чтобы оператор не принял коллизию за внутренний сбой.
		log.Printf("api: %s %s: %v", r.Method, r.URL.Path, err)
		writeErr(w, http.StatusConflict, "already_exists",
			"storage path is not an application directory, nothing was written to disk")
	case errors.As(err, &maxErr):
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "request body exceeds upload limit")
	default:
		internalErr(w, r, err)
	}
}

// --- /download ---

// plain500 is internalErr's plain-text sibling for the download route.
func plain500(w http.ResponseWriter, r *http.Request, msg string, err error) {
	log.Printf("api: %s %s: %v", r.Method, r.URL.Path, err)
	http.Error(w, msg, http.StatusInternalServerError)
}

// download serves the version's binary. Errors are plain text here (per plan
// this is acceptable for the download endpoints).
func (s *server) download(w http.ResponseWriter, r *http.Request) {
	a, err := s.st.GetApp(r.PathValue("name"))
	if err != nil {
		plain500(w, r, "internal error", err)
		return
	}
	if a == nil {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	var v *store.Version
	if ver := r.PathValue("version"); ver == "latest" {
		v, err = s.st.LatestVersion(a.ID)
	} else {
		var canon string
		canon, err = naming.ValidateVersion(ver)
		if err != nil {
			http.Error(w, "version not found", http.StatusNotFound)
			return
		}
		v, err = s.st.GetVersion(a.ID, canon)
	}
	if err != nil {
		plain500(w, r, "internal error", err)
		return
	}
	if v == nil {
		http.Error(w, "version not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(s.fs.Path(a.Name, v.Version, v.Filename))
	if err != nil {
		// Строка в БД есть, файла нет — рассинхрон хранилища, честный 500.
		plain500(w, r, "stored file unavailable", err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		plain500(w, r, "stored file unavailable", err)
		return
	}
	// FormatMediaType кодирует не-ASCII имена по RFC 2231/5987 (filename*=).
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{"filename": v.Filename}))
	w.Header().Set("X-Checksum-Sha256", v.SHA256)
	// ServeContent: Content-Length, Content-Type по расширению, Range — бесплатно.
	http.ServeContent(w, r, v.Filename, fi.ModTime(), f)
}
