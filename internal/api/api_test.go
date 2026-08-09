package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/api"
	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/files"
	"apprepo/internal/store"
)

const (
	testUser = "alice"
	testPass = "secret-pass"
	baseURL  = "http://repo.example"
)

// newMux builds a mux with the api routes over a fresh store, files root and
// one Basic Auth user.
func newMux(t *testing.T) *http.ServeMux {
	mux, _ := newMuxDir(t)
	return mux
}

// newMuxDir is newMux plus the files root, for tests that inspect the disk.
func newMuxDir(t *testing.T) (*http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "apprepo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, err := auth.HashPassword(testPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(testUser, hash, string(auth.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api.Register(mux, st, &files.Storage{Root: dir}, &auth.Auth{Store: st}, config.Config{
		BaseURL:        baseURL,
		MaxUploadBytes: 1 << 20,
	})
	return mux, dir
}

// do performs an authenticated request and returns the recorder. Непустое тело
// по умолчанию едет с Content-Type: application/json — этого требует рубеж
// notJSON (F14), и для тестов, которые проверяют не его, а поведение маршрута,
// заголовок не деталь постановки, а обязательная часть корректного запроса.
// Явный hdr перекрывает умолчание: тесты самого рубежа шлют, что хотят.
func do(t *testing.T, mux *http.ServeMux, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetBasicAuth(testUser, testPass)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON %q: %v", w.Body.String(), err)
	}
	return m
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, code, w.Body.String())
	}
}

// wantErr asserts an error response with the contract JSON shape.
func wantErr(t *testing.T, w *httptest.ResponseRecorder, code int, errCode string) {
	t.Helper()
	wantStatus(t, w, code)
	if m := decode(t, w); m["error"] != errCode {
		t.Fatalf("error code = %v, want %q; body: %s", m["error"], errCode, w.Body.String())
	}
}

func createApp(t *testing.T, mux *http.ServeMux, name string) {
	t.Helper()
	w := do(t, mux, "POST", "/api/apps", `{"name":"`+name+`","description":"d"}`, nil)
	wantStatus(t, w, http.StatusCreated)
}

// putVersion заливает версию с явным ?filename= — параметр обязателен (T23),
// так что тесты, проверяющие не его, шлют осмысленное имя вида {app}-{version}.
// Имя берётся из версии как передана, канонизация («v1.2.0» → «1.2.0») его не
// трогает: имя файла — то, что прислал клиент.
//
// `&platform=any` — по той же причине: тела в этих тестах текстовые, платформа
// по ним не определяется, и без параметра заливка отказала бы (T25). Тесты
// самой платформы шлют свой параметр и свои тела.
func putVersion(t *testing.T, mux *http.ServeMux, app, version, content string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, mux, "PUT",
		"/api/apps/"+app+"/versions/"+version+"?filename="+app+"-"+version+"&platform=any", content, hdr)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestUnauthorized(t *testing.T) {
	mux := newMux(t)
	for _, path := range []string{"/api/apps", "/download/app/1.0.0"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", path, w.Code)
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s: missing WWW-Authenticate", path)
		}
		if path == "/api/apps" { // для /api тело — JSON unauthorized
			if m := decode(t, w); m["error"] != "unauthorized" {
				t.Fatalf("%s: body = %s, want unauthorized JSON", path, w.Body.String())
			}
		}
	}
}

func TestCreateApp(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	wantErr(t, do(t, mux, "POST", "/api/apps", `{"name":"myapp"}`, nil),
		http.StatusConflict, "already_exists")
	wantErr(t, do(t, mux, "POST", "/api/apps", `{"name":"../evil"}`, nil),
		http.StatusBadRequest, "invalid_name")
	wantErr(t, do(t, mux, "POST", "/api/apps", `{"name":"latest"}`, nil),
		http.StatusBadRequest, "invalid_name")
}

func TestPutAndGetVersion(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")

	content := "binary-bytes-v1"
	w := putVersion(t, mux, "myapp", "v1.2.0", content,
		map[string]string{"X-Checksum-Sha256": strings.ToUpper(sha256hex(content))})
	wantStatus(t, w, http.StatusCreated)
	m := decode(t, w)
	if m["version"] != "1.2.0" { // канонизация без префикса v
		t.Fatalf("version = %v, want 1.2.0", m["version"])
	}
	if m["filename"] != "myapp-v1.2.0" { // имя файла — как прислал клиент
		t.Fatalf("filename = %v, want myapp-v1.2.0", m["filename"])
	}
	if m["sha256"] != sha256hex(content) {
		t.Fatalf("sha256 = %v, want %s", m["sha256"], sha256hex(content))
	}
	if m["download_url"] != baseURL+"/download/myapp/1.2.0" {
		t.Fatalf("download_url = %v", m["download_url"])
	}
	if m["is_latest"] != true {
		t.Fatalf("is_latest = %v, want true", m["is_latest"])
	}
	if m["size_bytes"] != float64(len(content)) {
		t.Fatalf("size_bytes = %v, want %d", m["size_bytes"], len(content))
	}

	// Повтор той же версии → 409.
	wantErr(t, putVersion(t, mux, "myapp", "1.2.0", "other", nil),
		http.StatusConflict, "already_exists")
	// Несуществующее приложение → 404.
	wantErr(t, putVersion(t, mux, "nope", "1.0.0", "x", nil),
		http.StatusNotFound, "not_found")
	// Невалидная версия → 400.
	wantErr(t, putVersion(t, mux, "myapp", "abc", "x", nil),
		http.StatusBadRequest, "invalid_version")
	// Невалидный filename → 400.
	wantErr(t, do(t, mux, "PUT", "/api/apps/myapp/versions/2.0.0?filename=..", "x", nil),
		http.StatusBadRequest, "invalid_filename")

	// GET объекта версии.
	w = do(t, mux, "GET", "/api/apps/myapp/versions/1.2.0", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["version"] != "1.2.0" || m["is_latest"] != true {
		t.Fatalf("get version body: %s", w.Body.String())
	}
	wantErr(t, do(t, mux, "GET", "/api/apps/myapp/versions/9.9.9", "", nil),
		http.StatusNotFound, "not_found")
}

func TestPutHashMismatch(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	w := putVersion(t, mux, "myapp", "1.0.0", "content",
		map[string]string{"X-Checksum-Sha256": strings.Repeat("0", 64)})
	wantErr(t, w, http.StatusUnprocessableEntity, "hash_mismatch")
	// Версия не создана и файла нет — повторная заливка проходит.
	wantErr(t, do(t, mux, "GET", "/api/apps/myapp/versions/1.0.0", "", nil),
		http.StatusNotFound, "not_found")
	wantStatus(t, putVersion(t, mux, "myapp", "1.0.0", "content", nil), http.StatusCreated)
}

func TestPutTooLarge(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	w := putVersion(t, mux, "myapp", "1.0.0", strings.Repeat("x", 1<<20+1), nil)
	wantErr(t, w, http.StatusRequestEntityTooLarge, "too_large")
}

func TestLatestResolution(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")

	// Без версий → 404.
	wantErr(t, do(t, mux, "GET", "/api/apps/myapp/latest", "", nil),
		http.StatusNotFound, "not_found")

	wantStatus(t, putVersion(t, mux, "myapp", "1.9.1", "old", nil), http.StatusCreated)
	wantStatus(t, putVersion(t, mux, "myapp", "1.10.0", "new", nil), http.StatusCreated)

	// Auto: максимум semver (1.10.0 > 1.9.1).
	w := do(t, mux, "GET", "/api/apps/myapp/latest", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["version"] != "1.10.0" {
		t.Fatalf("latest = %v, want 1.10.0", m["version"])
	}

	// Закрепить 1.9.1.
	w = do(t, mux, "POST", "/api/apps/myapp/latest", `{"version":"1.9.1"}`, nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["version"] != "1.9.1" {
		t.Fatalf("pinned latest = %v, want 1.9.1", m["version"])
	}
	w = do(t, mux, "GET", "/api/apps/myapp/latest", "", nil)
	if m := decode(t, w); m["version"] != "1.9.1" {
		t.Fatalf("latest after pin = %v, want 1.9.1", m["version"])
	}

	// Закрепить несуществующую → 404.
	wantErr(t, do(t, mux, "POST", "/api/apps/myapp/latest", `{"version":"9.9.9"}`, nil),
		http.StatusNotFound, "not_found")

	// Снять закрепление.
	w = do(t, mux, "POST", "/api/apps/myapp/latest", `{"version":"auto"}`, nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["version"] != "1.10.0" {
		t.Fatalf("latest after auto = %v, want 1.10.0", m["version"])
	}
}

func TestListsAndIsLatest(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	wantStatus(t, putVersion(t, mux, "myapp", "1.0.0", "a", nil), http.StatusCreated)
	wantStatus(t, putVersion(t, mux, "myapp", "2.0.0", "b", nil), http.StatusCreated)

	// GET /api/apps: массив с versions_count и latest-объектом.
	w := do(t, mux, "GET", "/api/apps", "", nil)
	wantStatus(t, w, http.StatusOK)
	var apps []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &apps); err != nil || len(apps) != 1 {
		t.Fatalf("apps list: %s (err %v)", w.Body.String(), err)
	}
	if apps[0]["versions_count"] != float64(2) {
		t.Fatalf("versions_count = %v, want 2", apps[0]["versions_count"])
	}
	latest, _ := apps[0]["latest"].(map[string]any)
	if latest == nil || latest["version"] != "2.0.0" {
		t.Fatalf("latest = %v, want 2.0.0", apps[0]["latest"])
	}

	// GET /api/apps/{name}/versions: semver desc, is_latest только у первой.
	w = do(t, mux, "GET", "/api/apps/myapp/versions", "", nil)
	wantStatus(t, w, http.StatusOK)
	var vs []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &vs); err != nil || len(vs) != 2 {
		t.Fatalf("versions list: %s (err %v)", w.Body.String(), err)
	}
	if vs[0]["version"] != "2.0.0" || vs[0]["is_latest"] != true || vs[1]["is_latest"] != false {
		t.Fatalf("versions order/is_latest wrong: %s", w.Body.String())
	}

	// GET /api/apps/{name}: детальный объект со списком версий.
	w = do(t, mux, "GET", "/api/apps/myapp", "", nil)
	wantStatus(t, w, http.StatusOK)
	m := decode(t, w)
	if m["name"] != "myapp" || m["versions"] == nil {
		t.Fatalf("app detail: %s", w.Body.String())
	}
	wantErr(t, do(t, mux, "GET", "/api/apps/nope", "", nil), http.StatusNotFound, "not_found")
	// F7/S4: имя из URL проверяется через naming до похода в БД — 404, как в UI.
	wantErr(t, do(t, mux, "GET", "/api/apps/..%2Fx", "", nil), http.StatusNotFound, "not_found")

	// Неизвестный API-путь → JSON 404.
	wantErr(t, do(t, mux, "GET", "/api/unknown", "", nil), http.StatusNotFound, "not_found")
}

func TestDownload(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	content := "downloadable-binary-content"
	wantStatus(t, putVersion(t, mux, "myapp", "1.0.0", content, nil), http.StatusCreated)

	for _, path := range []string{"/download/myapp/1.0.0", "/download/myapp/latest"} {
		w := do(t, mux, "GET", path, "", nil)
		wantStatus(t, w, http.StatusOK)
		if got := w.Body.String(); got != content {
			t.Fatalf("%s: body = %q, want %q", path, got, content)
		}
		if got := w.Header().Get("X-Checksum-Sha256"); got != sha256hex(content) {
			t.Fatalf("%s: X-Checksum-Sha256 = %q", path, got)
		}
		cd := w.Header().Get("Content-Disposition")
		if !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, "myapp-1.0.0") {
			t.Fatalf("%s: Content-Disposition = %q", path, cd)
		}
		if got := w.Header().Get("Content-Length"); got != "27" {
			t.Fatalf("%s: Content-Length = %q, want 27", path, got)
		}
	}

	// 404-ветки.
	for _, path := range []string{
		"/download/nope/1.0.0",    // нет приложения
		"/download/myapp/2.0.0",   // нет версии
		"/download/myapp/not-ver", // невалидная версия
	} {
		w := do(t, mux, "GET", path, "", nil)
		wantStatus(t, w, http.StatusNotFound)
	}

	// latest без версий → 404.
	createApp(t, mux, "empty")
	wantStatus(t, do(t, mux, "GET", "/download/empty/latest", "", nil), http.StatusNotFound)
}
