// Package integration contains end-to-end tests of the fully wired service
// (app.New → httptest.Server), covering waves 3–4: auth, web UI, JSON API,
// downloads and the integration wiring. Задача R4-test из плана
// docs/plans/2026-08-06-app-artifactory.md.
package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/app"
	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/store"
)

const (
	testUser = "alice"
	testPass = "s3cret-pass"
	// baseURL нарочно отличается от адреса httptest-сервера: проверяем, что
	// download_url строится от cfg.BaseURL, а не от Host запроса.
	testBaseURL = "http://repo.example"
	// testPlatform — платформа, которой помечаются тестовые заглушки: их тела
	// текстовые, автоопределение по ним ничего не даёт, а "any" ровно и значит
	// «файл не зависит от ОС и архитектуры» (T24–T26).
	testPlatform = "any"
)

type env struct {
	t       *testing.T
	srv     *httptest.Server
	st      *store.Store
	cfg     config.Config
	dataDir string
}

// newEnv boots the complete application on a temp dir with one user
// (alice/s3cret-pass) and returns a running httptest server around it.
func newEnv(t *testing.T, maxUpload int64) *env {
	t.Helper()
	root := t.TempDir()
	cfg := config.Config{
		Addr:           ":0",
		DataDir:        filepath.Join(root, "data"),
		DBPath:         filepath.Join(root, "data", "apprepo.db"),
		BaseURL:        testBaseURL,
		MaxUploadBytes: maxUpload,
	}
	h, st, err := app.New(cfg)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	hash, err := auth.HashPassword(testPass)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := st.CreateUser(testUser, hash, string(auth.RoleAdmin)); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, cfg: cfg, dataDir: cfg.DataDir}
}

// --- API (Basic Auth) helpers ---

// api performs an HTTP request with Basic Auth credentials of the test user.
func (e *env) api(method, path string, body io.Reader, hdr map[string]string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	req.SetBasicAuth(testUser, testPass)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// anon performs a request without any credentials.
func (e *env) anon(method, path string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatalf("NewRequest: %v", err)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// createApp creates an app over the API and asserts 201.
func (e *env) createApp(name string) {
	e.t.Helper()
	resp := e.api("POST", "/api/apps", strings.NewReader(`{"name":"`+name+`","description":"test app"}`), jsonHdr)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("create app %s: status = %d, want 201; body: %s", name, resp.StatusCode, readBody(e.t, resp))
	}
}

// putVersion uploads raw bytes via the API PUT endpoint and returns the response.
// An empty query gets ?filename={app}-{version}: the parameter is required since
// T23, and tests that check something other than the filename keep the name the
// API used to default to. The version goes in as passed — canonicalisation
// ("v1.2.0" → "1.2.0") does not touch the filename, it is what the client sent.
func (e *env) putVersion(app, version, query string, body []byte, sha string) *http.Response {
	e.t.Helper()
	if query == "" {
		query = "?filename=" + app + "-" + version
	}
	// Тела здешних заливок — текстовые заглушки, платформа по ним не
	// определяется (T25), и без явного ?platform= это 400 platform_required.
	// "any" — верная метка для файла, который не зависит от ОС и архитектуры;
	// тест, которому платформа важна, задаёт её сам в query.
	if !strings.Contains(query, "platform=") {
		query += "&platform=" + testPlatform
	}
	hdr := map[string]string{}
	if sha != "" {
		hdr["X-Checksum-Sha256"] = sha
	}
	return e.api("PUT", "/api/apps/"+app+"/versions/"+version+query, bytes.NewReader(body), hdr)
}

// mustPutVersion uploads and asserts 201, returning the decoded version object.
func (e *env) mustPutVersion(app, version, query string, body []byte, sha string) map[string]any {
	e.t.Helper()
	resp := e.putVersion(app, version, query, body, sha)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("PUT %s/%s: status = %d, want 201; body: %s", app, version, resp.StatusCode, readBody(e.t, resp))
	}
	return decodeJSON(e.t, resp)
}

var jsonHdr = map[string]string{"Content-Type": "application/json"}

// --- UI (session cookie) helpers ---

// uiClient is an HTTP client with a cookie jar that does not follow redirects,
// so tests can assert on 303s explicitly.
func (e *env) uiClient() *http.Client {
	e.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// csrfOf returns the CSRF cookie value the server issued to this client.
func (e *env) csrfOf(c *http.Client) string {
	e.t.Helper()
	u, _ := url.Parse(e.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "apprepo_csrf" {
			return ck.Value
		}
	}
	return ""
}

// login performs the full UI login flow (GET form for CSRF, then POST) and
// asserts the 303 redirect to next.
func (e *env) login(c *http.Client, next string) {
	e.t.Helper()
	resp, err := c.Get(e.srv.URL + "/login")
	if err != nil {
		e.t.Fatalf("GET /login: %v", err)
	}
	resp.Body.Close()
	tok := e.csrfOf(c)
	if tok == "" {
		e.t.Fatal("no CSRF cookie after GET /login")
	}
	form := url.Values{
		"csrf_token": {tok},
		"username":   {testUser},
		"password":   {testPass},
		"next":       {next},
	}
	resp, err = c.PostForm(e.srv.URL+"/login", form)
	if err != nil {
		e.t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("POST /login: status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != next {
		e.t.Fatalf("POST /login: Location = %q, want %q", loc, next)
	}
}

// uploadUI uploads a file through the UI multipart form. Field order matters:
// the handler streams parts and expects the file part last (as in the template).
func (e *env) uploadUI(c *http.Client, appName, version, sha, filename string, content []byte, csrfToken string) *http.Response {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// platform_os=any по той же причине, что и ?platform=any в putVersion:
	// содержимое текстовое, определить по нему нечего, а UI с T26 отклоняет
	// заливку с неизвестной платформой.
	for k, v := range map[string]string{"csrf_token": csrfToken, "version": version, "sha256": sha, "platform_os": testPlatform} {
		if err := mw.WriteField(k, v); err != nil {
			e.t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		e.t.Fatalf("CreateFormFile: %v", err)
	}
	fw.Write(content)
	mw.Close()
	req, err := http.NewRequest("POST", e.srv.URL+"/apps/"+appName+"/versions", &buf)
	if err != nil {
		e.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("POST upload: %v", err)
	}
	return resp
}

// --- misc helpers ---

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return m
}

// wantJSONError asserts the contract error object {"error": code} and status.
func wantJSONError(t *testing.T, resp *http.Response, status int, code string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, status, readBody(t, resp))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	m := decodeJSON(t, resp)
	if m["error"] != code {
		t.Errorf(`error code = %v, want %q`, m["error"], code)
	}
}
