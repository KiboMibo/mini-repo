package web_test

// Тесты гоняются локально с временной заглушкой internal/auth (контрактные
// сигнатуры); с реальным auth от T4 поведение перепроверяется в T7/R4-test.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/files"
	"apprepo/internal/store"
	"apprepo/internal/web"
)

type env struct {
	mux     *http.ServeMux
	st      *store.Store
	fs      *files.Storage
	session string
	root    string
}

const csrfTok = "testtoken"

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := auth.HashPassword("secret-pass")
	if err := st.CreateUser("alice", hash, string(auth.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUser("alice")
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	sess, err := st.CreateSession(u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fst := &files.Storage{Root: root}
	mux := http.NewServeMux()
	web.Register(mux, st, fst, &auth.Auth{Store: st}, config.Config{
		Addr: ":0", DataDir: root, BaseURL: "http://test", MaxUploadBytes: 1 << 20,
	})
	return &env{mux: mux, st: st, fs: fst, session: sess, root: root}
}

// do performs a request as the env's admin user with a valid CSRF cookie.
func (e *env) do(t *testing.T, method, target, ctype string, body io.Reader, withCSRFCookie bool) *httptest.ResponseRecorder {
	t.Helper()
	return e.doAs(t, e.session, method, target, ctype, body, withCSRFCookie)
}

// doAs performs a request on behalf of the owner of the given session token.
func (e *env) doAs(t *testing.T, session, method, target, ctype string, body io.Reader, withCSRFCookie bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.AddCookie(&http.Cookie{Name: "apprepo_session", Value: session})
	if withCSRFCookie {
		req.AddCookie(&http.Cookie{Name: "apprepo_csrf", Value: csrfTok})
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func form(vals map[string]string) (io.Reader, string) {
	u := make([]string, 0, len(vals))
	for k, v := range vals {
		u = append(u, k+"="+strings.ReplaceAll(v, " ", "+"))
	}
	return strings.NewReader(strings.Join(u, "&")), "application/x-www-form-urlencoded"
}

// multipartBody builds an upload body; fields go before the file part, as the
// UI form does.
func multipartBody(t *testing.T, fields map[string]string, filename string, content []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if filename != "" {
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(content)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

// addVersion stores a real file plus its DB row, the way an upload would.
func (e *env) addVersion(t *testing.T, app *store.App, version, filename, content string) {
	t.Helper()
	sha, size, err := e.fs.Save(app.Name, version, filename, strings.NewReader(content), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateVersion(app.ID, version, filename, size, sha); err != nil {
		t.Fatal(err)
	}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", path, err)
	}
	return err == nil
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest("GET", "/", nil) // без сессионной куки
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("Location = %q, want /login?next=…", loc)
	}
}

func TestLoginAndNextRedirect(t *testing.T) {
	e := newEnv(t)
	body, ctype := form(map[string]string{
		"csrf_token": csrfTok, "next": "/apps/x", "username": "alice", "password": "secret-pass",
	})
	req := httptest.NewRequest("POST", "/login", body)
	req.Header.Set("Content-Type", ctype)
	req.AddCookie(&http.Cookie{Name: "apprepo_csrf", Value: csrfTok})
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/apps/x" {
		t.Fatalf("code=%d location=%q, want 303 /apps/x", rec.Code, rec.Header().Get("Location"))
	}

	// Неверный пароль — 401, сессионная кука не ставится.
	body, ctype = form(map[string]string{
		"csrf_token": csrfTok, "username": "alice", "password": "wrong-pass",
	})
	req = httptest.NewRequest("POST", "/login", body)
	req.Header.Set("Content-Type", ctype)
	req.AddCookie(&http.Cookie{Name: "apprepo_csrf", Value: csrfTok})
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "apprepo_session" {
			t.Fatal("session cookie set on failed login")
		}
	}
}

func TestLoginNextSanitized(t *testing.T) {
	e := newEnv(t)
	for _, next := range []string{"https://evil.example", "//evil.example", `/\evil`} {
		body, ctype := form(map[string]string{
			"csrf_token": csrfTok, "next": next, "username": "alice", "password": "secret-pass",
		})
		req := httptest.NewRequest("POST", "/login", body)
		req.Header.Set("Content-Type", ctype)
		req.AddCookie(&http.Cookie{Name: "apprepo_csrf", Value: csrfTok})
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("next=%q redirected to %q, want /", next, loc)
		}
	}
}

func TestCSRFMissingForbidden(t *testing.T) {
	e := newEnv(t)
	// Кука есть, поля нет.
	body, ctype := form(map[string]string{"name": "myapp"})
	if rec := e.do(t, "POST", "/apps", ctype, body, true); rec.Code != http.StatusForbidden {
		t.Fatalf("no field: code = %d, want 403", rec.Code)
	}
	// Поле есть, куки нет.
	body, ctype = form(map[string]string{"name": "myapp", "csrf_token": csrfTok})
	if rec := e.do(t, "POST", "/apps", ctype, body, false); rec.Code != http.StatusForbidden {
		t.Fatalf("no cookie: code = %d, want 403", rec.Code)
	}
	if app, _ := e.st.GetApp("myapp"); app != nil {
		t.Fatal("app created despite CSRF failure")
	}
}

func TestCreateApp(t *testing.T) {
	e := newEnv(t)
	// Невалидное имя — 400, ничего не создано.
	body, ctype := form(map[string]string{"csrf_token": csrfTok, "name": "..evil"})
	rec := e.do(t, "POST", "/apps", ctype, body, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid app name") {
		t.Fatalf("code = %d, body lacks error", rec.Code)
	}
	if apps, _ := e.st.ListApps(); len(apps) != 0 {
		t.Fatal("app created despite invalid name")
	}
	// Валидное — 303 на страницу приложения.
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "name": "myapp", "description": "demo"})
	rec = e.do(t, "POST", "/apps", ctype, body, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/apps/myapp" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if app, _ := e.st.GetApp("myapp"); app == nil {
		t.Fatal("app not created")
	}
	// Дубль — 409 с ошибкой на странице.
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "name": "myapp"})
	if rec := e.do(t, "POST", "/apps", ctype, body, true); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: code = %d, want 409", rec.Code)
	}
}

func TestUpload(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("binary payload")
	sum := sha256.Sum256(content)
	wantSHA := hex.EncodeToString(sum[:])

	// Верный sha256 → 303, файл на диске, версия в БД. platform_os=any —
	// содержимое здесь не бинарник, а платформу заливка требует (T26).
	body, ctype := multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "v1.0.0", "sha256": wantSHA,
		"platform_os": "any",
	}, "myapp-linux", content)
	rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, body: %s", rec.Code, rec.Body.String())
	}
	if b, err := os.ReadFile(e.fs.Path("myapp", "1.0.0", "myapp-linux")); err != nil || !bytes.Equal(b, content) {
		t.Fatalf("stored file wrong: %v", err)
	}
	if v, _ := e.st.GetVersion(app.ID, "1.0.0"); v == nil || v.SHA256 != wantSHA {
		t.Fatalf("version row wrong: %+v", v)
	}

	// Неверный sha256 → 422, ни файла, ни версии.
	body, ctype = multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "2.0.0", "sha256": strings.Repeat("0", 64),
		"platform_os": "any",
	}, "myapp-linux", content)
	rec = e.do(t, "POST", "/apps/myapp/versions", ctype, body, true)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "SHA-256 mismatch") {
		t.Fatalf("code = %d, want 422; body: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(e.fs.Path("myapp", "2.0.0", "myapp-linux")); !os.IsNotExist(err) {
		t.Fatal("rejected file was stored")
	}
	if v, _ := e.st.GetVersion(app.ID, "2.0.0"); v != nil {
		t.Fatal("rejected version inserted")
	}

	// Дубль версии → 409.
	body, ctype = multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "1.0.0",
	}, "other-name", content)
	if rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate version: code = %d, want 409", rec.Code)
	}

	// Невалидный semver → 400.
	body, ctype = multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "абв",
	}, "f", content)
	if rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad version: code = %d, want 400", rec.Code)
	}

	// Без CSRF-токена в полях → 403, файл не сохранён.
	body, ctype = multipartBody(t, map[string]string{"version": "3.0.0"}, "f", content)
	if rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true); rec.Code != http.StatusForbidden {
		t.Fatalf("upload without csrf: code = %d, want 403", rec.Code)
	}
	if v, _ := e.st.GetVersion(app.ID, "3.0.0"); v != nil {
		t.Fatal("version created despite CSRF failure")
	}
}

func TestUploadTooLarge(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), 2<<20) // 2 MiB > лимита 1 MiB
	body, ctype := multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "1.0.0",
	}, "big", big)
	rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rec.Code)
	}
}

func TestSetLatest(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if _, err := e.st.CreateVersion(app.ID, v, "f-"+v, 1, strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
	}
	// Закрепить 1.0.0.
	body, ctype := form(map[string]string{"csrf_token": csrfTok, "version": "1.0.0"})
	if rec := e.do(t, "POST", "/apps/myapp/latest", ctype, body, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("pin: code = %d", rec.Code)
	}
	if v, _ := e.st.LatestVersion(app.ID); v == nil || v.Version != "1.0.0" {
		t.Fatalf("latest = %+v, want pinned 1.0.0", v)
	}
	// Вернуть auto.
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "version": "auto"})
	if rec := e.do(t, "POST", "/apps/myapp/latest", ctype, body, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("auto: code = %d", rec.Code)
	}
	if v, _ := e.st.LatestVersion(app.ID); v == nil || v.Version != "2.0.0" {
		t.Fatalf("latest = %+v, want auto 2.0.0", v)
	}
	// Несуществующая версия → 400.
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "version": "9.9.9"})
	if rec := e.do(t, "POST", "/apps/myapp/latest", ctype, body, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown version: code = %d, want 400", rec.Code)
	}
}

func TestPages(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "demo app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateVersion(app.ID, "1.2.3", "myapp-bin", 42, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	// Индекс: имя, описание, latest.
	rec := e.do(t, "GET", "/", "", nil, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("index code = %d", rec.Code)
	}
	for _, want := range []string{"myapp", "demo app", "1.2.3"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("index lacks %q", want)
		}
	}
	// Страница приложения: ссылка на скачивание и бейдж latest.
	rec = e.do(t, "GET", "/apps/myapp", "", nil, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("app page code = %d", rec.Code)
	}
	for _, want := range []string{`/download/myapp/1.2.3`, "latest", "myapp-bin"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("app page lacks %q", want)
		}
	}
	// CSRF-кука выставляется на GET.
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "apprepo_csrf" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("GET app page did not set apprepo_csrf cookie")
	}
	// Несуществующее приложение → 404.
	if rec := e.do(t, "GET", "/apps/nosuch", "", nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("nosuch app code = %d, want 404", rec.Code)
	}
}

// TestModalDialogs: формы создания и загрузки спрятаны в <dialog>; без ошибки
// диалог закрыт, при ошибке формы рендерится сразу открытым (атрибут open),
// чтобы ошибка осталась видимой пользователю.
func TestModalDialogs(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	// Обычный GET — диалоги закрыты.
	rec := e.do(t, "GET", "/", "", nil, false)
	if !strings.Contains(rec.Body.String(), `<dialog id="new-app-dialog">`) {
		t.Error("index lacks closed new-app dialog")
	}
	rec = e.do(t, "GET", "/apps/myapp", "", nil, false)
	if !strings.Contains(rec.Body.String(), `<dialog id="upload-dialog">`) {
		t.Error("app page lacks closed upload dialog")
	}
	// Ошибка формы — диалог открыт, ошибка в разметке.
	body, ctype := form(map[string]string{"csrf_token": csrfTok, "name": "..evil"})
	rec = e.do(t, "POST", "/apps", ctype, body, true)
	if !strings.Contains(rec.Body.String(), `<dialog id="new-app-dialog" open>`) {
		t.Error("create-app error page lacks open dialog")
	}
	body2, ctype2 := multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "not-semver",
	}, "myapp-bin", []byte("data"))
	rec = e.do(t, "POST", "/apps/myapp/versions", ctype2, body2, true)
	if !strings.Contains(rec.Body.String(), `<dialog id="upload-dialog" open>`) {
		t.Error("upload error page lacks open dialog")
	}
}

// TestUploadTooManyFields: множество не-file частей формы — 400 до чтения
// файла, память под поля не растёт с телом (лимит maxUploadFields).
func TestUploadTooManyFields(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{"csrf_token": csrfTok, "version": "1.0.0"}
	for i := 0; i < 20; i++ { // заведомо больше лимита maxUploadFields (8)
		fields["junk"+string(rune('a'+i))] = "x"
	}
	body, ctype := multipartBody(t, fields, "myapp-linux", []byte("data"))
	rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too many form fields") {
		t.Fatalf("code = %d, want 400 too many form fields; body: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(e.fs.Path("myapp", "1.0.0", "myapp-linux")); !os.IsNotExist(err) {
		t.Fatal("file must not be stored")
	}
}

// TestEditAppRename: имя и описание меняются, каталог переезжает на диске,
// ссылки на странице ведут на новое имя.
func TestEditAppRename(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "old description")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "myapp-bin", "payload")

	body, ctype := form(map[string]string{
		"csrf_token": csrfTok, "name": "renamed", "description": "new description",
	})
	rec := e.do(t, "POST", "/apps/myapp/edit", ctype, body, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/apps/renamed" {
		t.Fatalf("code=%d location=%q, want 303 /apps/renamed", rec.Code, rec.Header().Get("Location"))
	}
	if a, _ := e.st.GetApp("renamed"); a == nil || a.Description != "new description" {
		t.Fatalf("renamed row = %+v", a)
	}
	if a, _ := e.st.GetApp("myapp"); a != nil {
		t.Fatal("old name still in store")
	}
	// Каталог на диске переехал целиком.
	if !exists(t, e.fs.Path("renamed", "1.0.0", "myapp-bin")) {
		t.Fatal("file missing under the new app directory")
	}
	if exists(t, filepath.Join(e.root, "myapp")) {
		t.Fatal("old app directory still on disk")
	}
	// Ссылки на странице — под новым именем.
	page := e.do(t, "GET", "/apps/renamed", "", nil, false).Body.String()
	if !strings.Contains(page, "/download/renamed/1.0.0") {
		t.Error("app page lacks download link under the new name")
	}
	if strings.Contains(page, "/download/myapp/") {
		t.Error("app page still links to the old name")
	}
	if e.do(t, "GET", "/apps/myapp", "", nil, false).Code != http.StatusNotFound {
		t.Error("old app page still resolves")
	}
}

// TestEditAppNameTaken: переименование в занятое имя — ошибка на странице,
// на диске ничего не двигается.
func TestEditAppNameTaken(t *testing.T) {
	e := newEnv(t)
	one, err := e.st.CreateApp("one", "")
	if err != nil {
		t.Fatal(err)
	}
	two, err := e.st.CreateApp("two", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, one, "1.0.0", "one-bin", "one payload")
	e.addVersion(t, two, "2.0.0", "two-bin", "two payload")

	body, ctype := form(map[string]string{"csrf_token": csrfTok, "name": "two"})
	rec := e.do(t, "POST", "/apps/one/edit", ctype, body, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("code = %d, want 409 with an error; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `<dialog id="edit-dialog" open>`) {
		t.Error("edit dialog not re-opened with the error")
	}
	if a, _ := e.st.GetApp("one"); a == nil {
		t.Fatal("app one disappeared")
	}
	if !exists(t, e.fs.Path("one", "1.0.0", "one-bin")) ||
		!exists(t, e.fs.Path("two", "2.0.0", "two-bin")) {
		t.Fatal("files were touched by the rejected rename")
	}
}

// TestDeleteAppConfirm: без точного совпадения имени в поле confirm не
// удаляется ничего; с совпадением — редирект на список и пустой диск.
func TestDeleteAppConfirm(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "myapp-bin", "payload")
	other, err := e.st.CreateApp("keepme", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, other, "1.0.0", "keep-bin", "keep")

	for _, confirm := range []string{"", "MyApp", "myapp2"} {
		body, ctype := form(map[string]string{"csrf_token": csrfTok, "confirm": confirm})
		rec := e.do(t, "POST", "/apps/myapp/delete", ctype, body, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("confirm=%q: code = %d, want 400", confirm, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `<dialog id="delete-dialog" open>`) {
			t.Errorf("confirm=%q: delete dialog not re-opened with the error", confirm)
		}
		if a, _ := e.st.GetApp("myapp"); a == nil {
			t.Fatalf("confirm=%q: app deleted without a matching confirmation", confirm)
		}
		if !exists(t, e.fs.Path("myapp", "1.0.0", "myapp-bin")) {
			t.Fatalf("confirm=%q: file deleted without a matching confirmation", confirm)
		}
	}

	body, ctype := form(map[string]string{"csrf_token": csrfTok, "confirm": "myapp"})
	rec := e.do(t, "POST", "/apps/myapp/delete", ctype, body, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("code=%d location=%q, want 303 /", rec.Code, rec.Header().Get("Location"))
	}
	if a, _ := e.st.GetApp("myapp"); a != nil {
		t.Fatal("app row survived deletion")
	}
	if vs, _ := e.st.ListVersions(app.ID); len(vs) != 0 {
		t.Fatalf("versions survived deletion: %d", len(vs))
	}
	if exists(t, filepath.Join(e.root, "myapp")) {
		t.Fatal("app directory still on disk")
	}
	// Соседнее приложение не задето.
	if !exists(t, e.fs.Path("keepme", "1.0.0", "keep-bin")) {
		t.Fatal("another app's file was deleted")
	}
}

// TestDeleteVersion: удаляется только выбранная версия — её строка и файл;
// остальные версии приложения целы.
func TestDeleteVersion(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "bin-1", "one")
	e.addVersion(t, app, "2.0.0", "bin-2", "two")

	rec := e.do(t, "GET", "/apps/myapp", "", nil, false)
	if !strings.Contains(rec.Body.String(), "/apps/myapp/versions/1.0.0/delete") {
		t.Error("app page lacks the per-version delete form")
	}

	body, ctype := form(map[string]string{"csrf_token": csrfTok})
	rec = e.do(t, "POST", "/apps/myapp/versions/v1.0.0/delete", ctype, body, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/apps/myapp" {
		t.Fatalf("code=%d location=%q, want 303 /apps/myapp", rec.Code, rec.Header().Get("Location"))
	}
	if v, _ := e.st.GetVersion(app.ID, "1.0.0"); v != nil {
		t.Fatal("version row survived deletion")
	}
	if exists(t, filepath.Join(e.root, "myapp", "1.0.0")) {
		t.Fatal("version directory still on disk")
	}
	if v, _ := e.st.GetVersion(app.ID, "2.0.0"); v == nil {
		t.Fatal("the other version was deleted too")
	}
	if !exists(t, e.fs.Path("myapp", "2.0.0", "bin-2")) {
		t.Fatal("the other version's file was deleted too")
	}
	// Несуществующая версия — 404.
	body, ctype = form(map[string]string{"csrf_token": csrfTok})
	if rec := e.do(t, "POST", "/apps/myapp/versions/9.9.9/delete", ctype, body, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown version: code = %d, want 404", rec.Code)
	}
}

// TestEditDeleteCSRF: три новых POST без токена — 403, состояние не менялось.
func TestEditDeleteCSRF(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "keep")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "myapp-bin", "payload")

	targets := map[string]map[string]string{
		"/apps/myapp/edit":                  {"name": "renamed"},
		"/apps/myapp/delete":                {"confirm": "myapp"},
		"/apps/myapp/versions/1.0.0/delete": {},
	}
	for target, fields := range targets {
		body, ctype := form(fields) // кука есть, поля csrf_token нет
		if rec := e.do(t, "POST", target, ctype, body, true); rec.Code != http.StatusForbidden {
			t.Errorf("%s without token: code = %d, want 403", target, rec.Code)
		}
		withField := map[string]string{"csrf_token": csrfTok}
		for k, v := range fields {
			withField[k] = v
		}
		body, ctype = form(withField) // поле есть, куки нет
		if rec := e.do(t, "POST", target, ctype, body, false); rec.Code != http.StatusForbidden {
			t.Errorf("%s without cookie: code = %d, want 403", target, rec.Code)
		}
	}
	a, _ := e.st.GetApp("myapp")
	if a == nil || a.Description != "keep" {
		t.Fatalf("app changed despite CSRF failures: %+v", a)
	}
	if v, _ := e.st.GetVersion(app.ID, "1.0.0"); v == nil {
		t.Fatal("version deleted despite CSRF failure")
	}
	if !exists(t, e.fs.Path("myapp", "1.0.0", "myapp-bin")) {
		t.Fatal("file deleted despite CSRF failure")
	}
}

// TestEditAppRenameRevertsOnDiskFailure: строка БД переименована, но каталог
// переехать не смог (цель уже занята) — имя откатывается, чтобы БД не
// указывала на несуществующий каталог. Занятая цель — конфликт, а не сбой:
// 409, как и в api.updateApp для того же files.ErrFileExists (F10/В2).
func TestEditAppRenameRevertsOnDiskFailure(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "keep me")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "myapp-bin", "payload")
	// Каталог-самозванец без строки в БД: UpdateApp пройдёт, RenameApp — нет.
	if err := os.Mkdir(filepath.Join(e.root, "renamed"), 0o700); err != nil {
		t.Fatal(err)
	}

	body, ctype := form(map[string]string{"csrf_token": csrfTok, "name": "renamed"})
	rec := e.do(t, "POST", "/apps/myapp/edit", ctype, body, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `<dialog id="edit-dialog" open>`) {
		t.Error("edit dialog not re-opened with the error")
	}
	a, _ := e.st.GetApp("myapp")
	if a == nil || a.Description != "keep me" {
		t.Fatalf("name was not reverted in the store: %+v", a)
	}
	if a, _ := e.st.GetApp("renamed"); a != nil {
		t.Fatal("store still holds the new name after a failed disk rename")
	}
	if !exists(t, e.fs.Path("myapp", "1.0.0", "myapp-bin")) {
		t.Fatal("file left the original directory")
	}
}

// TestDeleteAppNamedLikeANeighbourFile (F7/S1): Storage.Root — это data-dir, в
// котором лежит и файл БД; его имя проходит naming. Удаление приложения с таким
// именем не должно снести файл: 409, файл на месте, сервис жив.
func TestDeleteAppNamedLikeANeighbourFile(t *testing.T) {
	e := newEnv(t)
	victim := filepath.Join(e.root, "test.db") // база этого env
	if !exists(t, victim) {
		t.Fatalf("нет файла БД %s — тест потерял смысл", victim)
	}
	if _, err := e.st.CreateApp("test.db", ""); err != nil {
		t.Fatal(err)
	}

	body, ctype := form(map[string]string{"csrf_token": csrfTok, "confirm": "test.db"})
	rec := e.do(t, "POST", "/apps/test.db/delete", ctype, body, true)
	if rec.Code != http.StatusConflict {
		t.Errorf("code = %d, want 409; body: %s", rec.Code, rec.Body.String())
	}
	if !exists(t, victim) {
		t.Fatal("UI-удаление приложения снесло файл БД")
	}
	if strings.Contains(rec.Body.String(), e.root) {
		t.Error("путь ФС утёк в ответ клиенту")
	}
	if apps, err := e.st.ListApps(); err != nil || len(apps) != 0 {
		t.Errorf("строка приложения не удалена: %v, %v", apps, err)
	}
}
