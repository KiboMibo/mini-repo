package integration

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/auth"
	"apprepo/internal/store"
)

// TestSameVersionViaUIAndAPI: одна и та же версия через UI и API — второй
// канал получает 409, содержимое первого не затирается (краевой из плана).
func TestSameVersionViaUIAndAPI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("shared")
	csrf := e.csrfOf(c)

	t.Run("ui_first_then_api_put_is_409", func(t *testing.T) {
		uiContent := []byte("from-ui")
		resp := e.uploadUI(c, "shared", "1.0.0", "", "ui-bin", uiContent, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("UI upload: status = %d, want 303", resp.StatusCode)
		}

		apiResp := e.putVersion("shared", "1.0.0", "", []byte("from-api"), "")
		wantJSONError(t, apiResp, http.StatusConflict, "already_exists")

		// PUT с префиксом v той же версии — тоже 409 (каноникализация).
		apiResp = e.putVersion("shared", "v1.0.0", "", []byte("from-api"), "")
		wantJSONError(t, apiResp, http.StatusConflict, "already_exists")

		dl := e.api("GET", "/download/shared/1.0.0", nil, nil)
		defer dl.Body.Close()
		if got := readBody(t, dl); got != string(uiContent) {
			t.Errorf("после 409 содержимое подменилось: got %q, want %q", got, uiContent)
		}
	})

	t.Run("api_first_then_ui_upload_is_409", func(t *testing.T) {
		apiContent := []byte("api-owns-this")
		e.mustPutVersion("shared", "2.0.0", "", apiContent, "")

		resp := e.uploadUI(c, "shared", "2.0.0", "", "ui-bin2", []byte("ui-late"), csrf)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("UI upload дубля: status = %d, want 409", resp.StatusCode)
		}
		if body := readBody(t, resp); !strings.Contains(body, "already exists") {
			t.Errorf("на странице нет сообщения о существующей версии")
		}

		dl := e.api("GET", "/download/shared/2.0.0", nil, nil)
		defer dl.Body.Close()
		if got := readBody(t, dl); got != string(apiContent) {
			t.Errorf("после 409 содержимое подменилось: got %q, want %q", got, apiContent)
		}
	})
}

// TestLatestWithPrerelease: контракт, зафиксированный R2-test, — prerelease
// старшего мажора СТАНОВИТСЯ latest (2.0.0-rc.1 > 1.9.1). Проверяем, что UI
// и API показывают один и тот же latest и download/latest отдаёт его же.
func TestLatestWithPrerelease(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("pre")
	stable := []byte("stable-1.9.1")
	rc := []byte("rc-2.0.0")
	e.mustPutVersion("pre", "1.9.1", "", stable, "")
	e.mustPutVersion("pre", "1.9.0-rc.1", "", []byte("old-rc"), "")
	e.mustPutVersion("pre", "2.0.0-rc.1", "", rc, "")

	t.Run("api_latest_is_prerelease_of_higher_major", func(t *testing.T) {
		resp := e.api("GET", "/api/apps/pre/latest", nil, nil)
		defer resp.Body.Close()
		obj := decodeJSON(t, resp)
		if obj["version"] != "2.0.0-rc.1" {
			t.Errorf("latest = %v, want 2.0.0-rc.1 (контракт R2-test)", obj["version"])
		}
	})

	t.Run("prerelease_of_same_minor_does_not_beat_stable", func(t *testing.T) {
		// Список semver desc: 2.0.0-rc.1, 1.9.1, 1.9.0-rc.1.
		resp := e.api("GET", "/api/apps/pre/versions", nil, nil)
		defer resp.Body.Close()
		body := readBody(t, resp)
		i191 := strings.Index(body, `"version":"1.9.1"`)
		irc190 := strings.Index(body, `"version":"1.9.0-rc.1"`)
		if i191 < 0 || irc190 < 0 || i191 > irc190 {
			t.Errorf("порядок версий неверен: 1.9.1 должна идти раньше 1.9.0-rc.1; body: %s", body)
		}
	})

	t.Run("download_latest_serves_prerelease_bytes", func(t *testing.T) {
		resp := e.api("GET", "/download/pre/latest", nil, nil)
		defer resp.Body.Close()
		if got := readBody(t, resp); got != string(rc) {
			t.Errorf("download/latest: got %q, want %q (2.0.0-rc.1)", got, rc)
		}
	})

	t.Run("ui_shows_same_latest_as_api", func(t *testing.T) {
		c := e.uiClient()
		e.login(c, "/")
		page := e.getPage(c, "/apps/pre")
		if !strings.Contains(page, "Latest: <strong>2.0.0-rc.1</strong>") {
			t.Errorf("страница приложения не показывает latest 2.0.0-rc.1 — расхождение UI и API")
		}
		if !strings.Contains(page, "(auto)") {
			t.Errorf("latest должен быть auto, не pinned")
		}
		// Бейдж latest — у строки таблицы prerelease-версии (не у "Latest:" в шапке).
		rowStart := strings.Index(page, "<td>2.0.0-rc.1")
		if rowStart < 0 {
			t.Fatalf("нет строки таблицы для 2.0.0-rc.1")
		}
		row := page[rowStart:]
		if i := strings.Index(row, "</tr>"); i > 0 {
			row = row[:i]
		}
		if !strings.Contains(row, `<span class="badge">latest</span>`) {
			t.Errorf("бейдж latest не на строке 2.0.0-rc.1")
		}
		// Индексная страница консистентна.
		index := e.getPage(c, "/")
		if !strings.Contains(index, "2.0.0-rc.1") {
			t.Errorf("индексная страница не показывает latest 2.0.0-rc.1")
		}
	})

	t.Run("api_objects_agree_on_is_latest", func(t *testing.T) {
		resp := e.api("GET", "/api/apps/pre/versions/2.0.0-rc.1", nil, nil)
		defer resp.Body.Close()
		if obj := decodeJSON(t, resp); obj["is_latest"] != true {
			t.Errorf("is_latest у 2.0.0-rc.1 = %v, want true", obj["is_latest"])
		}
		resp = e.api("GET", "/api/apps/pre/versions/1.9.1", nil, nil)
		defer resp.Body.Close()
		if obj := decodeJSON(t, resp); obj["is_latest"] != false {
			t.Errorf("is_latest у 1.9.1 = %v, want false", obj["is_latest"])
		}
	})
}

// TestHealthz: /healthz открыт без аутентификации (для systemd и мониторинга).
func TestHealthz(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	resp := e.anon("GET", "/healthz")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if body := readBody(t, resp); strings.TrimSpace(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
}

// TestUserAddCLI: `apprepo user add` с APPREPO_PASSWORD создаёт пользователя,
// пароль которого проходит проверку (критерий приёмки T7, без интерактива).
func TestUserAddCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("сборка бинарника — пропускаем в -short")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "apprepo")
	build := exec.Command("go", "build", "-o", bin, "apprepo/cmd/apprepo")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	dataDir := filepath.Join(root, "data")
	run := func(env []string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), env...)
		cmd.Stdin = strings.NewReader("") // не терминал: интерактивный ввод недоступен
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run %v: %v\n%s", args, err, out)
		}
		return string(out), code
	}

	t.Run("user_add_with_env_password_creates_user", func(t *testing.T) {
		out, code := run([]string{"APPREPO_PASSWORD=cli-pass"}, "user", "add", "bob", "-data-dir", dataDir)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; out: %s", code, out)
		}
		st, err := store.Open(filepath.Join(dataDir, "apprepo.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		defer st.Close()
		u, err := st.GetUser("bob")
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if u == nil {
			t.Fatal("пользователь bob не создан")
		}
		if !auth.CheckPassword(u.PasswordHash, "cli-pass") {
			t.Error("пароль из APPREPO_PASSWORD не проходит CheckPassword")
		}
		if auth.CheckPassword(u.PasswordHash, "wrong") {
			t.Error("неверный пароль не должен проходить")
		}
	})

	// Начиная с волны 6 всякий пользователь, кроме самого первого, обязан
	// назвать роль, поэтому подтесты ниже передают -role: проверяются дубль
	// имени и пустой пароль, а не разбор аргументов.
	t.Run("user_add_duplicate_fails", func(t *testing.T) {
		out, code := run([]string{"APPREPO_PASSWORD=other-password"},
			"user", "add", "bob", "-role", "developer", "-data-dir", dataDir)
		if code != 1 || !strings.Contains(out, "already exists") {
			t.Errorf("exit = %d, out = %q; want 1 и 'already exists'", code, out)
		}
	})

	// F13: политика длины пароля одна на три интерфейса, и CLI — единственный
	// из них, который ходит в БД мимо HTTP; без этой проверки коротким паролем
	// можно было бы завести учётку в обход API и UI.
	t.Run("user_add_short_password_fails", func(t *testing.T) {
		out, code := run([]string{"APPREPO_PASSWORD=short"},
			"user", "add", "shorty", "-role", "developer", "-data-dir", dataDir)
		if code != 1 || !strings.Contains(out, "at least 8 bytes") {
			t.Errorf("exit = %d, out = %q; want 1 и 'at least 8 bytes'", code, out)
		}
		st, err := store.Open(filepath.Join(dataDir, "apprepo.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		defer st.Close()
		if u, err := st.GetUser("shorty"); err != nil || u != nil {
			t.Errorf("учётка с коротким паролем всё же создана: %+v (err %v)", u, err)
		}
	})

	t.Run("user_add_without_password_non_tty_fails", func(t *testing.T) {
		out, code := run(nil, "user", "add", "carol", "-role", "developer", "-data-dir", dataDir)
		if code != 1 || !strings.Contains(out, "empty password") {
			t.Errorf("exit = %d, out = %q; want 1 и 'empty password'", code, out)
		}
	})

	t.Run("user_add_second_without_role_fails", func(t *testing.T) {
		out, code := run([]string{"APPREPO_PASSWORD=dave-password"}, "user", "add", "dave", "-data-dir", dataDir)
		if code != 2 || !strings.Contains(out, "-role is required") {
			t.Errorf("exit = %d, out = %q; want 2 и '-role is required'", code, out)
		}
		for _, role := range auth.AllRoles() {
			if !strings.Contains(out, string(role)) {
				t.Errorf("в сообщении нет роли %q; out: %s", role, out)
			}
		}
	})

	t.Run("user_without_add_prints_usage", func(t *testing.T) {
		out, code := run(nil, "user")
		if code != 2 || !strings.Contains(out, "usage") {
			t.Errorf("exit = %d, out = %q; want 2 и usage", code, out)
		}
	})

	t.Run("unknown_command_prints_usage", func(t *testing.T) {
		out, code := run(nil, "frobnicate")
		if code != 2 || !strings.Contains(out, "unknown command") {
			t.Errorf("exit = %d, out = %q; want 2 и 'unknown command'", code, out)
		}
	})

	t.Run("serve_with_unusable_db_path_fails", func(t *testing.T) {
		// Путь БД — каталог: app.New не сможет открыть БД, serve падает.
		badDB := filepath.Join(root, "db-as-dir")
		if err := os.MkdirAll(badDB, 0o755); err != nil {
			t.Fatal(err)
		}
		_, code := run(nil, "serve", "-data-dir", dataDir, "-db", badDB)
		if code == 0 {
			t.Error("serve с каталогом вместо БД должен завершаться с ошибкой")
		}
	})

	t.Run("bad_flag_exits_2", func(t *testing.T) {
		_, code := run(nil, "serve", "-no-such-flag")
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})
}
