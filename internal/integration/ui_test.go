package integration

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUIHappyPath: полный пользовательский сценарий через веб-UI — редирект
// на логин, вход, создание приложения, загрузка с верным SHA-256, назначение
// и снятие latest, скачивание залитого через UI файла по Basic Auth.
func TestUIHappyPath(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()

	t.Run("unauthenticated_root_redirects_to_login_with_next", func(t *testing.T) {
		resp, err := c.Get(e.srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "/login?next=%2F" {
			t.Errorf("Location = %q, want /login?next=%%2F", loc)
		}
	})

	e.login(c, "/")

	t.Run("root_after_login_renders_app_list", func(t *testing.T) {
		resp, err := c.Get(e.srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if body := readBody(t, resp); !strings.Contains(body, "No applications yet") {
			t.Errorf("пустой список должен содержать 'No applications yet'")
		}
	})

	csrf := e.csrfOf(c)

	t.Run("create_app_via_form_redirects_to_app_page", func(t *testing.T) {
		resp, err := c.PostForm(e.srv.URL+"/apps", url.Values{
			"csrf_token":  {csrf},
			"name":        {"webapp"},
			"description": {"uploaded from UI"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "/apps/webapp" {
			t.Errorf("Location = %q, want /apps/webapp", loc)
		}
	})

	content := []byte("ui-binary-content")

	t.Run("upload_with_correct_sha_adds_version", func(t *testing.T) {
		resp := e.uploadUI(c, "webapp", "1.0.0", sha256hex(content), "webapp-bin", content, csrf)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body: %s", resp.StatusCode, readBody(t, resp))
		}
		if _, err := os.Stat(filepath.Join(e.dataDir, "webapp", "1.0.0", "webapp-bin")); err != nil {
			t.Errorf("файл не появился на диске: %v", err)
		}
		page := e.getPage(c, "/apps/webapp")
		if !strings.Contains(page, "1.0.0") || !strings.Contains(page, "webapp-bin") {
			t.Errorf("страница приложения не содержит версию/файл")
		}
		if !strings.Contains(page, `href="/download/webapp/1.0.0"`) {
			t.Errorf("нет прямой ссылки на скачивание")
		}
		if !strings.Contains(page, `<span class="badge">latest</span>`) {
			t.Errorf("нет бейджа latest у единственной версии")
		}
	})

	t.Run("uploaded_via_ui_downloads_via_basic_auth", func(t *testing.T) {
		resp := e.api("GET", "/download/webapp/1.0.0", nil, nil)
		defer resp.Body.Close()
		if got := readBody(t, resp); got != string(content) {
			t.Errorf("байты: got %q, want %q", got, content)
		}
		if got := resp.Header.Get("X-Checksum-Sha256"); got != sha256hex(content) {
			t.Errorf("X-Checksum-Sha256 = %q, want %s", got, sha256hex(content))
		}
	})

	t.Run("pin_latest_and_back_to_auto", func(t *testing.T) {
		second := []byte("second-version")
		resp := e.uploadUI(c, "webapp", "1.1.0", "", "webapp-bin2", second, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("upload 1.1.0: status = %d, want 303", resp.StatusCode)
		}

		// Закрепить 1.0.0.
		resp, err := c.PostForm(e.srv.URL+"/apps/webapp/latest", url.Values{
			"csrf_token": {csrf}, "version": {"1.0.0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("pin: status = %d, want 303", resp.StatusCode)
		}
		page := e.getPage(c, "/apps/webapp")
		if !strings.Contains(page, "Latest: <strong>1.0.0</strong>") || !strings.Contains(page, "(pinned)") {
			t.Errorf("после закрепления страница должна показывать Latest 1.0.0 (pinned)")
		}

		// Вернуть auto → 1.1.0.
		resp, err = c.PostForm(e.srv.URL+"/apps/webapp/latest", url.Values{
			"csrf_token": {csrf}, "version": {"auto"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		page = e.getPage(c, "/apps/webapp")
		if !strings.Contains(page, "Latest: <strong>1.1.0</strong>") || !strings.Contains(page, "(auto)") {
			t.Errorf("после auto страница должна показывать Latest 1.1.0 (auto)")
		}
	})
}

// getPage GETs a UI path with the client and returns the body, asserting 200.
func (e *env) getPage(c *http.Client, path string) string {
	e.t.Helper()
	resp, err := c.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET %s: status = %d, want 200", path, resp.StatusCode)
	}
	return readBody(e.t, resp)
}

// TestUILoginWrongPassword: неверный пароль — 401 и куки сессии нет.
func TestUILoginWrongPassword(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	resp, err := c.Get(e.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.PostForm(e.srv.URL+"/login", url.Values{
		"csrf_token": {e.csrfOf(c)},
		"username":   {testUser},
		"password":   {"wrong"},
		"next":       {"/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(readBody(t, resp), "invalid username or password") {
		t.Errorf("нет человекочитаемой ошибки на странице логина")
	}
	u, _ := url.Parse(e.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "apprepo_session" && ck.Value != "" {
			t.Errorf("кука сессии не должна ставиться при неверном пароле")
		}
	}
}

// TestUICreateAppInvalidName: форма с ошибкой, ничего не создано.
func TestUICreateAppInvalidName(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	resp, err := c.PostForm(e.srv.URL+"/apps", url.Values{
		"csrf_token": {e.csrfOf(c)},
		"name":       {"../evil"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	apps, err := e.st.ListApps()
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Errorf("приложений в БД %d, want 0", len(apps))
	}
}

// TestUIUploadWrongSHA: ошибка на странице, файла нет ни на диске, ни в БД.
func TestUIUploadWrongSHA(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("webapp")
	resp := e.uploadUI(c, "webapp", "1.0.0", strings.Repeat("f", 64), "bin", []byte("data"), e.csrfOf(c))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", resp.StatusCode)
	}
	if !strings.Contains(readBody(t, resp), "SHA-256 mismatch") {
		t.Errorf("нет человекочитаемой ошибки о несовпадении хеша")
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "webapp", "1.0.0")); !os.IsNotExist(err) {
		t.Errorf("каталог версии не должен существовать, stat err = %v", err)
	}
	gv := e.api("GET", "/api/apps/webapp/versions/1.0.0", nil, nil)
	wantJSONError(t, gv, http.StatusNotFound, "not_found")
}

// TestCSRFProtection: POST без токена (или с чужим токеном) → 403,
// действие не выполняется (краевой из плана).
func TestCSRFProtection(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("target")

	t.Run("create_app_without_token_is_403", func(t *testing.T) {
		resp, err := c.PostForm(e.srv.URL+"/apps", url.Values{"name": {"intruder"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
		if a, _ := e.st.GetApp("intruder"); a != nil {
			t.Errorf("приложение создано без CSRF-токена")
		}
	})

	t.Run("create_app_with_wrong_token_is_403", func(t *testing.T) {
		resp, err := c.PostForm(e.srv.URL+"/apps", url.Values{
			"csrf_token": {"attacker-guess"}, "name": {"intruder2"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("upload_without_token_is_403_and_no_file", func(t *testing.T) {
		resp := e.uploadUI(c, "target", "1.0.0", "", "bin", []byte("data"), "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
		if _, err := os.Stat(filepath.Join(e.dataDir, "target", "1.0.0")); !os.IsNotExist(err) {
			t.Errorf("файл не должен сохраняться без CSRF-токена, stat err = %v", err)
		}
	})

	t.Run("set_latest_without_token_is_403", func(t *testing.T) {
		resp, err := c.PostForm(e.srv.URL+"/apps/target/latest", url.Values{"version": {"auto"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("login_without_token_is_403", func(t *testing.T) {
		c2 := e.uiClient()
		resp, err := c2.PostForm(e.srv.URL+"/login", url.Values{
			"username": {testUser}, "password": {testPass}, "next": {"/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
}

// TestUIOpenRedirectBlocked: next наружу сайта заменяется на "/".
func TestUIOpenRedirectBlocked(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	for _, next := range []string{"https://evil.example", "//evil.example", `/\evil.example`} {
		c := e.uiClient()
		resp, err := c.Get(e.srv.URL + "/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		resp, err = c.PostForm(e.srv.URL+"/login", url.Values{
			"csrf_token": {e.csrfOf(c)},
			"username":   {testUser},
			"password":   {testPass},
			"next":       {next},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Errorf("next=%q: Location = %q, want /", next, loc)
		}
	}
}
