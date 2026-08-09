package integration

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/app"
	"apprepo/internal/config"
)

// TestAPIListAndValidation: список приложений и валидационные ветки API.
func TestAPIListAndValidation(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("listed")
	e.mustPutVersion("listed", "1.0.0", "", []byte("bin"), "")

	t.Run("get_apps_returns_list_with_latest", func(t *testing.T) {
		resp := e.api("GET", "/api/apps", nil, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body := readBody(t, resp)
		if !strings.Contains(body, `"name":"listed"`) ||
			!strings.Contains(body, `"versions_count":1`) ||
			!strings.Contains(body, `"version":"1.0.0"`) {
			t.Errorf("список приложений неполон: %s", body)
		}
	})

	t.Run("create_app_with_invalid_json_is_400", func(t *testing.T) {
		resp := e.api("POST", "/api/apps", strings.NewReader("{not json"), jsonHdr)
		wantJSONError(t, resp, http.StatusBadRequest, "validation")
	})

	t.Run("routes_on_nonexistent_app_are_404", func(t *testing.T) {
		for _, p := range []string{
			"/api/apps/ghost", "/api/apps/ghost/versions",
			"/api/apps/ghost/versions/1.0.0", "/api/apps/ghost/latest",
		} {
			resp := e.api("GET", p, nil, nil)
			wantJSONError(t, resp, http.StatusNotFound, "not_found")
		}
		resp := e.api("POST", "/api/apps/ghost/latest", strings.NewReader(`{"version":"auto"}`), jsonHdr)
		wantJSONError(t, resp, http.StatusNotFound, "not_found")
	})

	t.Run("get_version_with_invalid_semver_is_400", func(t *testing.T) {
		resp := e.api("GET", "/api/apps/listed/versions/not-semver", nil, nil)
		wantJSONError(t, resp, http.StatusBadRequest, "invalid_version")
	})

	t.Run("set_latest_validation", func(t *testing.T) {
		resp := e.api("POST", "/api/apps/listed/latest", strings.NewReader("garbage"), jsonHdr)
		wantJSONError(t, resp, http.StatusBadRequest, "validation")

		resp = e.api("POST", "/api/apps/listed/latest", strings.NewReader(`{"version":"???"}`), jsonHdr)
		wantJSONError(t, resp, http.StatusBadRequest, "invalid_version")

		resp = e.api("POST", "/api/apps/listed/latest", strings.NewReader(`{"version":"9.9.9"}`), jsonHdr)
		wantJSONError(t, resp, http.StatusNotFound, "not_found")
	})

	t.Run("put_with_invalid_filename_is_400", func(t *testing.T) {
		resp := e.putVersion("listed", "3.0.0", "?filename=..", []byte("x"), "")
		wantJSONError(t, resp, http.StatusBadRequest, "invalid_filename")
	})
}

// TestDownloadDesyncedStorageIs500: строка в БД есть, файла на диске нет —
// честный 500, а не пустой файл.
func TestDownloadDesyncedStorageIs500(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("desync")
	e.mustPutVersion("desync", "1.0.0", "", []byte("bin"), "")
	if err := os.RemoveAll(filepath.Join(e.dataDir, "desync", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	resp := e.api("GET", "/download/desync/1.0.0", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 при рассинхроне БД и диска", resp.StatusCode)
	}
}

// TestUILogout: выход гасит сессию — повторный заход требует логина.
func TestUILogout(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	resp, err := c.PostForm(e.srv.URL+"/logout", url.Values{"csrf_token": {e.csrfOf(c)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
	resp, err = c.Get(e.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("после logout GET / должен редиректить на логин, status = %d", resp.StatusCode)
	}
}

// TestUIEdges: 404/400-ветки UI-хендлеров.
func TestUIEdges(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("edgy")
	e.mustPutVersion("edgy", "1.0.0", "", []byte("bin"), "")
	csrf := e.csrfOf(c)

	t.Run("unknown_app_page_is_404", func(t *testing.T) {
		for _, p := range []string{"/apps/ghost", "/apps/latest"} { // latest — запрещённое имя
			resp, err := c.Get(e.srv.URL + p)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status = %d, want 404", p, resp.StatusCode)
			}
		}
	})

	t.Run("upload_to_unknown_app_is_404", func(t *testing.T) {
		resp := e.uploadUI(c, "ghost", "1.0.0", "", "bin", []byte("x"), csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("non_multipart_upload_is_400", func(t *testing.T) {
		resp, err := c.PostForm(e.srv.URL+"/apps/edgy/versions", url.Values{
			"csrf_token": {csrf}, "version": {"2.0.0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("multipart_without_file_part_is_400", func(t *testing.T) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		mw.WriteField("csrf_token", csrf)
		mw.WriteField("version", "2.0.0")
		mw.Close()
		req, _ := http.NewRequest("POST", e.srv.URL+"/apps/edgy/versions", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
		if !strings.Contains(readBody(t, resp), "no file in upload") {
			t.Errorf("нет сообщения 'no file in upload'")
		}
	})

	t.Run("invalid_version_in_upload_is_400", func(t *testing.T) {
		resp := e.uploadUI(c, "edgy", "not.a.version.at.all", "", "bin", []byte("x"), csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("filename_with_path_is_stored_as_basename", func(t *testing.T) {
		resp := e.uploadRawFilename(c, "edgy", "3.0.0", `dir/sub/evil-bin`, []byte("x"), csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", resp.StatusCode)
		}
		if _, err := os.Stat(filepath.Join(e.dataDir, "edgy", "3.0.0", "evil-bin")); err != nil {
			t.Errorf("файл должен лежать под basename: %v", err)
		}
	})

	t.Run("dotdot_filename_is_rejected", func(t *testing.T) {
		resp := e.uploadRawFilename(c, "edgy", "4.0.0", "..", []byte("x"), csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
		if _, err := os.Stat(filepath.Join(e.dataDir, "edgy", "4.0.0")); !os.IsNotExist(err) {
			t.Errorf("каталог 4.0.0 не должен существовать, stat err = %v", err)
		}
	})

	t.Run("set_latest_edges", func(t *testing.T) {
		// Несуществующее приложение.
		resp, err := c.PostForm(e.srv.URL+"/apps/ghost/latest", url.Values{
			"csrf_token": {csrf}, "version": {"auto"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("ghost: status = %d, want 404", resp.StatusCode)
		}
		// Невалидный semver.
		resp, err = c.PostForm(e.srv.URL+"/apps/edgy/latest", url.Values{
			"csrf_token": {csrf}, "version": {"???"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid semver: status = %d, want 400", resp.StatusCode)
		}
		// Отсутствующая версия.
		resp, err = c.PostForm(e.srv.URL+"/apps/edgy/latest", url.Values{
			"csrf_token": {csrf}, "version": {"9.9.9"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("missing version: status = %d, want 400", resp.StatusCode)
		}
	})
}

// uploadRawFilename шлёт multipart с сырым filename в Content-Disposition
// (CreateFormFile не позволяет управлять экранированием).
func (e *env) uploadRawFilename(c *http.Client, appName, version, filename string, content []byte, csrfToken string) *http.Response {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("csrf_token", csrfToken)
	mw.WriteField("version", version)
	mw.WriteField("platform_os", testPlatform)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="file"; filename="`+filename+`"`)
	pw, err := mw.CreatePart(hdr)
	if err != nil {
		e.t.Fatal(err)
	}
	pw.Write(content)
	mw.Close()
	req, err := http.NewRequest("POST", e.srv.URL+"/apps/"+appName+"/versions", &buf)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// TestUIUploadTooLargeIs413: превышение max-upload в UI — страница с 413.
func TestUIUploadTooLargeIs413(t *testing.T) {
	const limit = 1024
	e := newEnv(t, limit)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("tiny")
	resp := e.uploadUI(c, "tiny", "1.0.0", "", "big", bytes.Repeat([]byte("x"), limit*2), e.csrfOf(c))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if !strings.Contains(readBody(t, resp), "too large") {
		t.Errorf("нет человекочитаемой ошибки о размере")
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "tiny", "1.0.0")); !os.IsNotExist(err) {
		t.Errorf("файл не должен сохраняться, stat err = %v", err)
	}
}

// TestAppNewErrors: конструктор приложения отдаёт ошибку, а не панику,
// когда data-dir или БД недоступны.
func TestAppNewErrors(t *testing.T) {
	root := t.TempDir()

	t.Run("data_dir_under_regular_file", func(t *testing.T) {
		block := filepath.Join(root, "blocker")
		if err := os.WriteFile(block, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		dataDir := filepath.Join(block, "data")
		_, _, err := app.New(config.Config{
			DataDir: dataDir,
			DBPath:  filepath.Join(dataDir, "db"),
		})
		if err == nil {
			t.Fatal("app.New должен вернуть ошибку, когда data-dir не создаётся")
		}
		// F6: по логу должно быть видно, где именно упало. os.MkdirAll отдаёт
		// *PathError на том компоненте, который не создался (здесь — файл-блокер;
		// при read-only ФС это будет сам каталог БД).
		if !strings.Contains(err.Error(), block) {
			t.Errorf("err = %q; в тексте нет пути %s", err, block)
		}
	})

	t.Run("db_path_is_a_directory", func(t *testing.T) {
		dataDir := filepath.Join(root, "data")
		dbAsDir := filepath.Join(dataDir, "db-dir")
		if err := os.MkdirAll(dbAsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, st, err := app.New(config.Config{DataDir: dataDir, DBPath: dbAsDir})
		if err == nil {
			st.Close()
			t.Fatal("app.New должен вернуть ошибку, когда путь БД — каталог")
		}
		// F6: в логе должно быть имя файла БД, иначе непонятно, что не открылось.
		if !strings.Contains(err.Error(), dbAsDir) {
			t.Errorf("err = %q; в тексте нет пути %s", err, dbAsDir)
		}
	})
}
