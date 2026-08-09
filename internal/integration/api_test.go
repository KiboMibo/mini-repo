package integration

import (
	"bytes"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const defaultMaxUpload = 1 << 20 // 1 MiB достаточно для всех сценариев кроме boundary

// TestAPIHappyPath повторяет полный сценарий scripts/smoke.sh как Go-тест:
// 401 без учёток → создать приложение → залить две версии (с хешем и без) →
// отклонить неверный хеш → latest = максимум semver → скачать и сверить байты
// и заголовки → закрепить latest → снять закрепление.
func TestAPIHappyPath(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)

	t.Run("unauthenticated_api_request_is_401_json", func(t *testing.T) {
		resp := e.anon("GET", "/api/apps")
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `Basic realm="apprepo"`) {
			t.Errorf("WWW-Authenticate = %q, want Basic realm=\"apprepo\"", got)
		}
		wantJSONError(t, resp, http.StatusUnauthorized, "unauthorized")
	})

	e.createApp("myapp")
	f1 := []byte("binary-one")
	f2 := []byte("binary-two-bigger")

	t.Run("put_with_correct_hash_returns_201_and_version_object", func(t *testing.T) {
		obj := e.mustPutVersion("myapp", "1.0.0", "", f1, sha256hex(f1))
		if obj["version"] != "1.0.0" {
			t.Errorf("version = %v, want 1.0.0", obj["version"])
		}
		if obj["filename"] != "myapp-1.0.0" {
			t.Errorf("filename = %v, want myapp-1.0.0 (as sent by the helper)", obj["filename"])
		}
		if obj["sha256"] != sha256hex(f1) {
			t.Errorf("sha256 = %v, want %s", obj["sha256"], sha256hex(f1))
		}
		if got := obj["size_bytes"]; got != float64(len(f1)) {
			t.Errorf("size_bytes = %v, want %d", got, len(f1))
		}
		if want := testBaseURL + "/download/myapp/1.0.0"; obj["download_url"] != want {
			t.Errorf("download_url = %v, want %s", obj["download_url"], want)
		}
		if obj["is_latest"] != true {
			t.Errorf("is_latest = %v, want true (единственная версия)", obj["is_latest"])
		}
	})

	t.Run("put_without_hash_and_custom_filename", func(t *testing.T) {
		obj := e.mustPutVersion("myapp", "1.2.0", "?filename=myapp-linux", f2, "")
		if obj["filename"] != "myapp-linux" {
			t.Errorf("filename = %v, want myapp-linux", obj["filename"])
		}
		if obj["sha256"] != sha256hex(f2) {
			t.Errorf("server-side sha256 = %v, want %s", obj["sha256"], sha256hex(f2))
		}
	})

	t.Run("put_with_wrong_hash_is_422_and_nothing_stored", func(t *testing.T) {
		wrong := strings.Repeat("a", 64)
		resp := e.putVersion("myapp", "2.0.0", "", f1, wrong)
		wantJSONError(t, resp, http.StatusUnprocessableEntity, "hash_mismatch")
		if _, err := os.Stat(filepath.Join(e.dataDir, "myapp", "2.0.0")); !os.IsNotExist(err) {
			t.Errorf("каталог myapp/2.0.0 не должен существовать после 422, stat err = %v", err)
		}
		gv := e.api("GET", "/api/apps/myapp/versions/2.0.0", nil, nil)
		wantJSONError(t, gv, http.StatusNotFound, "not_found")
	})

	t.Run("latest_is_max_semver", func(t *testing.T) {
		resp := e.api("GET", "/api/apps/myapp/latest", nil, nil)
		defer resp.Body.Close()
		obj := decodeJSON(t, resp)
		if obj["version"] != "1.2.0" {
			t.Errorf("latest = %v, want 1.2.0", obj["version"])
		}
		if obj["is_latest"] != true {
			t.Errorf("is_latest = %v, want true", obj["is_latest"])
		}
	})

	t.Run("download_latest_serves_bytes_and_headers", func(t *testing.T) {
		resp := e.api("GET", "/download/myapp/latest", nil, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body := readBody(t, resp)
		if !bytes.Equal([]byte(body), f2) {
			t.Errorf("скачанные байты отличаются от загруженных: got %q, want %q", body, f2)
		}
		if got := resp.Header.Get("X-Checksum-Sha256"); got != sha256hex(f2) {
			t.Errorf("X-Checksum-Sha256 = %q, want %s", got, sha256hex(f2))
		}
		cd := resp.Header.Get("Content-Disposition")
		disp, params, err := mime.ParseMediaType(cd)
		if err != nil || disp != "attachment" || params["filename"] != "myapp-linux" {
			t.Errorf("Content-Disposition = %q (err %v), want attachment; filename=myapp-linux", cd, err)
		}
		if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(f2)) {
			t.Errorf("Content-Length = %q, want %d", got, len(f2))
		}
	})

	t.Run("download_specific_version", func(t *testing.T) {
		resp := e.api("GET", "/download/myapp/1.0.0", nil, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if body := readBody(t, resp); !bytes.Equal([]byte(body), f1) {
			t.Errorf("байты версии 1.0.0: got %q, want %q", body, f1)
		}
	})

	t.Run("pin_latest_then_auto", func(t *testing.T) {
		resp := e.api("POST", "/api/apps/myapp/latest", strings.NewReader(`{"version":"1.0.0"}`), jsonHdr)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("pin: status = %d, want 200; body: %s", resp.StatusCode, readBody(t, resp))
		}
		if obj := decodeJSON(t, resp); obj["version"] != "1.0.0" {
			t.Errorf("pinned latest = %v, want 1.0.0", obj["version"])
		}

		dl := e.api("GET", "/download/myapp/latest", nil, nil)
		got := readBody(t, dl)
		dl.Body.Close()
		if !bytes.Equal([]byte(got), f1) {
			t.Errorf("после закрепления latest должен отдавать 1.0.0: got %q, want %q", got, f1)
		}

		resp = e.api("POST", "/api/apps/myapp/latest", strings.NewReader(`{"version":"auto"}`), jsonHdr)
		defer resp.Body.Close()
		if obj := decodeJSON(t, resp); obj["version"] != "1.2.0" {
			t.Errorf("после auto latest = %v, want 1.2.0", obj["version"])
		}
	})

	t.Run("app_listing_shape", func(t *testing.T) {
		resp := e.api("GET", "/api/apps/myapp", nil, nil)
		defer resp.Body.Close()
		obj := decodeJSON(t, resp)
		if obj["versions_count"] != float64(2) {
			t.Errorf("versions_count = %v, want 2", obj["versions_count"])
		}
		vs, ok := obj["versions"].([]any)
		if !ok || len(vs) != 2 {
			t.Fatalf("versions = %v, want массив из 2", obj["versions"])
		}
		first := vs[0].(map[string]any)
		second := vs[1].(map[string]any)
		if first["version"] != "1.2.0" || second["version"] != "1.0.0" {
			t.Errorf("порядок версий = [%v %v], want semver desc [1.2.0 1.0.0]", first["version"], second["version"])
		}
	})
}

// TestPutDuplicateVersionIs409: повторная заливка той же версии через API.
func TestPutDuplicateVersionIs409(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("dup")
	content := []byte("payload-v1")
	e.mustPutVersion("dup", "1.0.0", "", content, "")

	resp := e.putVersion("dup", "1.0.0", "", []byte("other-bytes"), "")
	wantJSONError(t, resp, http.StatusConflict, "already_exists")

	// Оригинальный файл не перезаписан.
	dl := e.api("GET", "/download/dup/1.0.0", nil, nil)
	defer dl.Body.Close()
	if got := readBody(t, dl); got != string(content) {
		t.Errorf("после 409 файл изменился: got %q, want %q", got, content)
	}
}

// TestAPIErrors: 404/400/409 на служебных маршрутах.
func TestAPIErrors(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("empty")

	t.Run("put_to_nonexistent_app_is_404", func(t *testing.T) {
		resp := e.putVersion("ghost", "1.0.0", "", []byte("x"), "")
		wantJSONError(t, resp, http.StatusNotFound, "not_found")
	})
	t.Run("create_duplicate_app_is_409", func(t *testing.T) {
		resp := e.api("POST", "/api/apps", strings.NewReader(`{"name":"empty"}`), jsonHdr)
		wantJSONError(t, resp, http.StatusConflict, "already_exists")
	})
	t.Run("create_app_with_invalid_name_is_400", func(t *testing.T) {
		for _, name := range []string{"latest", "../evil", ""} {
			resp := e.api("POST", "/api/apps", strings.NewReader(`{"name":"`+name+`"}`), jsonHdr)
			wantJSONError(t, resp, http.StatusBadRequest, "invalid_name")
		}
	})
	t.Run("put_invalid_version_is_400", func(t *testing.T) {
		resp := e.putVersion("empty", "not-semver", "", []byte("x"), "")
		wantJSONError(t, resp, http.StatusBadRequest, "invalid_version")
	})
	t.Run("latest_of_app_without_versions_is_404", func(t *testing.T) {
		resp := e.api("GET", "/api/apps/empty/latest", nil, nil)
		wantJSONError(t, resp, http.StatusNotFound, "not_found")
	})
	t.Run("unknown_api_route_is_json_404", func(t *testing.T) {
		resp := e.api("GET", "/api/nonsense", nil, nil)
		wantJSONError(t, resp, http.StatusNotFound, "not_found")
	})
}

// TestDownloadNonexistent: скачивание несуществующего (краевой из плана).
func TestDownloadNonexistent(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("solo")
	e.mustPutVersion("solo", "1.0.0", "", []byte("bin"), "")
	e.createApp("hollow") // без версий

	cases := []struct {
		name, path string
	}{
		{"nonexistent_app", "/download/ghost/1.0.0"},
		{"nonexistent_version", "/download/solo/9.9.9"},
		{"invalid_version_string", "/download/solo/not-a-version"},
		{"latest_of_app_without_versions", "/download/hollow/latest"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_is_404", func(t *testing.T) {
			resp := e.api("GET", tc.path, nil, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status = %d, want 404", tc.path, resp.StatusCode)
			}
		})
	}
}

// TestBasicAuthRejects: Basic Auth с несуществующим пользователем и неверным
// паролем (краевой из плана).
func TestBasicAuthRejects(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	e.mustPutVersion("myapp", "1.0.0", "", []byte("bin"), "")

	cases := []struct {
		name, user, pass string
	}{
		{"unknown_user", "nobody", "whatever"},
		{"wrong_password", testUser, "wrong-password"},
		{"empty_credentials", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_api_is_401", func(t *testing.T) {
			req, _ := http.NewRequest("GET", e.srv.URL+"/api/apps", nil)
			req.SetBasicAuth(tc.user, tc.pass)
			resp, err := e.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
				t.Errorf("WWW-Authenticate = %q, want Basic", got)
			}
			wantJSONError(t, resp, http.StatusUnauthorized, "unauthorized")
		})
		t.Run(tc.name+"_download_is_401", func(t *testing.T) {
			req, _ := http.NewRequest("GET", e.srv.URL+"/download/myapp/1.0.0", nil)
			req.SetBasicAuth(tc.user, tc.pass)
			resp, err := e.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
			if body := readBody(t, resp); strings.Contains(body, "binary") {
				t.Errorf("тело 401 не должно содержать файл: %q", body)
			}
		})
	}
}

// TestMaxUploadBoundary: загрузка ровно на границе max-upload и на байт выше
// (краевой из плана).
func TestMaxUploadBoundary(t *testing.T) {
	const limit = 1024
	e := newEnv(t, limit)
	e.createApp("edge")

	t.Run("body_exactly_at_limit_is_accepted", func(t *testing.T) {
		body := bytes.Repeat([]byte("x"), limit)
		obj := e.mustPutVersion("edge", "1.0.0", "", body, sha256hex(body))
		if obj["size_bytes"] != float64(limit) {
			t.Errorf("size_bytes = %v, want %d", obj["size_bytes"], limit)
		}
		dl := e.api("GET", "/download/edge/1.0.0", nil, nil)
		defer dl.Body.Close()
		if got := readBody(t, dl); len(got) != limit {
			t.Errorf("скачано %d байт, want %d", len(got), limit)
		}
	})

	t.Run("body_one_byte_over_limit_is_413_and_not_stored", func(t *testing.T) {
		body := bytes.Repeat([]byte("x"), limit+1)
		resp := e.putVersion("edge", "2.0.0", "", body, "")
		wantJSONError(t, resp, http.StatusRequestEntityTooLarge, "too_large")
		if _, err := os.Stat(filepath.Join(e.dataDir, "edge", "2.0.0")); !os.IsNotExist(err) {
			t.Errorf("каталог edge/2.0.0 не должен существовать после 413, stat err = %v", err)
		}
		// Временных остатков в .tmp тоже нет.
		entries, err := os.ReadDir(filepath.Join(e.dataDir, ".tmp"))
		if err == nil && len(entries) != 0 {
			t.Errorf("в .tmp остались файлы после 413: %d шт.", len(entries))
		}
	})
}
