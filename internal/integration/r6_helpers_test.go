package integration

// Хелперы сквозных сценариев волны 6 (роли и управление учётками, задачи
// T18–T21 + F11). Задача R6-test.
//
// Отличие от helpers_test.go: там всё ходит от единственного админа alice,
// здесь нужны произвольные учётки — Basic от кого угодно, UI-сессия от кого
// угодно и поднятие приложения на заранее подготовленном каталоге данных
// (сценарий обновления боевой БД и сценарий «CLI завёл, HTTP пустил»).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/app"
	"apprepo/internal/config"
	"apprepo/internal/naming"
	"apprepo/internal/store"
)

// cred — пара логин/пароль для Basic Auth. Пустой user означает «без креды».
type cred struct{ user, pass string }

var adminCred = cred{testUser, testPass}

// validPass — пароль-фикстура, годный по текущей политике. Считается от
// naming.MinPasswordBytes, а не пишется литералом, нарочно: подтест, который
// проверяет что-то ПОСЛЕ успешного создания учётки, при поднятии минимума
// иначе получает 400 на входе, выходит по раннему return и зеленеет вхолостую,
// ни разу не дойдя до своей проверки. Ровно эта ловушка описана в отчёте F12 и
// стоила приёмки находки об именах учёток; производная фикстура закрывает её
// навсегда — следующее поднятие минимума фикстуру не сломает.
var validPass = strings.Repeat("p", naming.MinPasswordBytes)

// cfgAt returns the standard test config rooted at dir (data-dir и БД внутри),
// как это делает newEnv.
func cfgAt(dir string, maxUpload int64) config.Config {
	return config.Config{
		Addr:           ":0",
		DataDir:        filepath.Join(dir, "data"),
		DBPath:         filepath.Join(dir, "data", "apprepo.db"),
		BaseURL:        testBaseURL,
		MaxUploadBytes: maxUpload,
	}
}

// bootEnv поднимает полное приложение на готовом cfg и НЕ создаёт учёток:
// они либо уже лежат в БД (миграция, CLI), либо заводятся тестом.
func bootEnv(t *testing.T, cfg config.Config) *env {
	t.Helper()
	h, st, err := app.New(cfg)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, cfg: cfg, dataDir: cfg.DataDir}
}

// --- API от произвольной учётки ---

// apiAs — как env.api, но с указанными кредами (пустой cred — без Basic).
func (e *env) apiAs(cr cred, method, path string, body io.Reader, hdr map[string]string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	if cr.user != "" {
		req.SetBasicAuth(cr.user, cr.pass)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s as %q: %v", method, path, cr.user, err)
	}
	return resp
}

// statusAs performs the request and returns its status and body, closing it.
func (e *env) statusAs(cr cred, method, path string, body io.Reader, hdr map[string]string) (int, string) {
	e.t.Helper()
	resp := e.apiAs(cr, method, path, body, hdr)
	defer resp.Body.Close()
	return resp.StatusCode, readBody(e.t, resp)
}

// wantStatusAs asserts the status of an API call made as cr.
func (e *env) wantStatusAs(cr cred, method, path string, body io.Reader, want int, why string) {
	e.t.Helper()
	code, text := e.statusAs(cr, method, path, body, jsonHdr)
	if code != want {
		e.t.Errorf("%s %s as %q: status = %d, want %d (%s); body: %s",
			method, path, cr.user, code, want, why, text)
	}
}

// --- учётки ---

// mkUser creates an account through the API as the admin and asserts 201.
func (e *env) mkUser(name, pass, role string) cred {
	e.t.Helper()
	body := `{"username":"` + name + `","password":"` + pass + `","role":"` + role + `"}`
	code, text := e.statusAs(adminCred, "POST", "/api/users", strings.NewReader(body), jsonHdr)
	if code != http.StatusCreated {
		e.t.Fatalf("POST /api/users %s/%s: status = %d, want 201; body: %s", name, role, code, text)
	}
	return cred{name, pass}
}

// patchUser applies a partial update to an account as the admin and returns
// status and body (409 last_admin/self_delete тоже интересны вызывающему).
func (e *env) patchUser(actor cred, name, body string) (int, string) {
	e.t.Helper()
	return e.statusAs(actor, "PATCH", "/api/users/"+name, strings.NewReader(body), jsonHdr)
}

// userID resolves a username to its numeric id — UI-маршруты учёток адресуют
// пользователя по id, а API по имени.
func (e *env) userID(name string) int64 {
	e.t.Helper()
	u := e.mustStoreUser(name)
	return u.ID
}

// mustStoreUser reads the user row straight from the store (проверка
// состояния, а не поведения: наружу хеш и disabled в одном месте не отдаются).
func (e *env) mustStoreUser(name string) *store.User {
	e.t.Helper()
	u, err := e.st.GetUser(name)
	if err != nil {
		e.t.Fatalf("GetUser(%q): %v", name, err)
	}
	if u == nil {
		e.t.Fatalf("пользователь %q не найден в БД", name)
	}
	return u
}

// --- UI от произвольной учётки ---

// loginAs performs the full UI login flow as cr and returns the status of the
// POST /login together with the client (кука уже в jar, если вход удался).
func (e *env) loginAs(cr cred, next string) (*http.Client, int) {
	e.t.Helper()
	c := e.uiClient()
	resp := e.uiGet(c, "/login")
	resp.Body.Close()
	tok := e.csrfOf(c)
	if tok == "" {
		e.t.Fatal("нет CSRF-куки после GET /login")
	}
	resp = e.uiPost(c, "/login", url.Values{
		"csrf_token": {tok},
		"username":   {cr.user},
		"password":   {cr.pass},
		"next":       {next},
	})
	defer resp.Body.Close()
	return c, resp.StatusCode
}

// mustLoginAs logs in through the UI and fails the test if the login itself
// was refused. Успешный вход не означает допуска в интерфейс: deployer входит,
// но на любой странице получает 403 (у роли нет PermUI).
func (e *env) mustLoginAs(cr cred) *http.Client {
	e.t.Helper()
	c, code := e.loginAs(cr, "/")
	if code != http.StatusSeeOther {
		e.t.Fatalf("POST /login as %q: status = %d, want 303", cr.user, code)
	}
	return c
}

// uiStatus performs a UI GET and returns status and body.
func (e *env) uiStatus(c *http.Client, path string) (int, string) {
	e.t.Helper()
	resp := e.uiGet(c, path)
	defer resp.Body.Close()
	return resp.StatusCode, readBody(e.t, resp)
}

// uiPostStatus submits an urlencoded form (CSRF подставляется из куки) and
// returns status and body.
func (e *env) uiPostStatus(c *http.Client, path string, form url.Values) (int, string) {
	e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", e.csrfOf(c))
	resp := e.uiPost(c, path, form)
	defer resp.Body.Close()
	return resp.StatusCode, readBody(e.t, resp)
}

// --- вердикты доступа ---

// deniedAPI reports whether the API answer is a permission refusal (403 с
// контрактным кодом forbidden), а не просто какой-нибудь 403.
func deniedAPI(t *testing.T, code int, body string) bool {
	t.Helper()
	if code != http.StatusForbidden {
		return false
	}
	if !strings.Contains(body, `"forbidden"`) {
		t.Errorf("403 без контрактного кода forbidden; body: %s", body)
	}
	return true
}

// deniedUI reports whether the UI answer is the role-refusal page. Отличать
// важно: 403 «invalid CSRF token» — ошибка теста, а не отказ по праву.
func deniedUI(t *testing.T, code int, body string) bool {
	t.Helper()
	if code != http.StatusForbidden {
		return false
	}
	if strings.Contains(body, "invalid CSRF token") {
		t.Fatalf("403 из-за CSRF, а не из-за роли — тест не подставил токен")
	}
	if !strings.Contains(body, "Not available for your role") {
		t.Errorf("403 не является страницей отказа по роли; body: %s", body)
	}
	return true
}

// sessionOf returns the session cookie value the server issued to this client.
func (e *env) sessionOf(c *http.Client) string {
	e.t.Helper()
	u, _ := url.Parse(e.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "apprepo_session" {
			return ck.Value
		}
	}
	return ""
}
