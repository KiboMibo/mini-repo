package integration

// CLI против HTTP: `apprepo user …` — аварийная дверь в установку, поэтому
// то, что он записал в БД, обязано немедленно отражаться на живом сервере.
// Проверяется на одном каталоге данных: CLI пишет своим процессом, сервер
// поднят через app.New в этом же тесте.

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/auth"
)

// cliRunner builds the binary once and returns a runner over a fixed data dir.
func cliRunner(t *testing.T, dataDir string) func(env []string, args ...string) (string, int) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "apprepo")
	build := exec.Command("go", "build", "-o", bin, "apprepo/cmd/apprepo")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return func(extraEnv []string, args ...string) (string, int) {
		t.Helper()
		args = append(args, "-data-dir", dataDir)
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), extraEnv...)
		cmd.Stdin = strings.NewReader("") // не терминал: интерактива нет
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run %v: %v\n%s", args, err, out)
		}
		return string(out), code
	}
}

// TestCLIAccountsVisibleOverHTTP: учётка, заведённая через `apprepo user add
// -role`, входит по HTTP ровно с этой ролью; `user disable` немедленно
// закрывает доступ, `user enable` возвращает, `user role` меняет права на
// живом сервере, `user delete` даёт 401.
func TestCLIAccountsVisibleOverHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("сборка бинарника — пропускаем в -short")
	}
	root := t.TempDir()
	cfg := cfgAt(root, defaultMaxUpload)
	run := cliRunner(t, cfg.DataDir)

	// Первый пользователь без -role — админ (иначе установку некому вести).
	if out, code := run([]string{"APPREPO_PASSWORD=root-pass"}, "user", "add", "root"); code != 0 {
		t.Fatalf("user add root: exit = %d; out: %s", code, out)
	}
	for _, role := range auth.AllRoles() {
		out, code := run([]string{"APPREPO_PASSWORD=pw-" + string(role)},
			"user", "add", "cli-"+string(role), "-role", string(role))
		if code != 0 {
			t.Fatalf("user add cli-%s: exit = %d; out: %s", role, code, out)
		}
		if !strings.Contains(out, string(role)) {
			t.Errorf("вывод user add не называет роль %s: %s", role, out)
		}
	}

	// Сервер поднимается ПОСЛЕ CLI и на том же каталоге.
	e := bootEnv(t, cfg)

	t.Run("роль_из_CLI_видна_по_HTTP", func(t *testing.T) {
		for _, role := range auth.AllRoles() {
			cr := cred{"cli-" + string(role), "pw-" + string(role)}
			code, body := e.statusAs(cr, "GET", "/api/me", nil, nil)
			if code != http.StatusOK {
				t.Errorf("%s: GET /api/me status = %d, want 200; body: %s", cr.user, code, body)
				continue
			}
			if !strings.Contains(body, `"role":"`+string(role)+`"`) {
				t.Errorf("%s: /api/me = %s, want role %s", cr.user, body, role)
			}
		}
	})

	t.Run("права_соответствуют_роли_из_CLI", func(t *testing.T) {
		// deployer читает, но не создаёт приложений.
		dep := cred{"cli-deployer", "pw-deployer"}
		e.wantStatusAs(dep, "GET", "/api/apps", nil, http.StatusOK, "PermRead")
		code, body := e.statusAs(dep, "POST", "/api/apps",
			strings.NewReader(`{"name":"from-deployer"}`), jsonHdr)
		if !deniedAPI(t, code, body) {
			t.Errorf("deployer из CLI создал приложение: status = %d, want 403", code)
		}
		// maintainer — создаёт.
		mnt := cred{"cli-maintainer", "pw-maintainer"}
		e.wantStatusAs(mnt, "POST", "/api/apps",
			strings.NewReader(`{"name":"from-maintainer"}`), http.StatusCreated, "PermApp")
		// и не управляет учётками.
		code, body = e.statusAs(mnt, "GET", "/api/users", nil, nil)
		if !deniedAPI(t, code, body) {
			t.Errorf("maintainer из CLI получил список учёток: status = %d, want 403", code)
		}
	})

	t.Run("user_disable_закрывает_доступ_немедленно", func(t *testing.T) {
		dev := cred{"cli-developer", "pw-developer"}
		e.wantStatusAs(dev, "GET", "/api/me", nil, http.StatusOK, "до блокировки")
		session := e.mustLoginAs(dev)
		e.wantSessionAlive(session, "до блокировки")

		if out, code := run(nil, "user", "disable", "cli-developer"); code != 0 {
			t.Fatalf("user disable: exit = %d; out: %s", code, out)
		}
		e.wantBasicDead(dev, "user disable")
		e.wantSessionDead(session, "user disable")

		if out, code := run(nil, "user", "enable", "cli-developer"); code != 0 {
			t.Fatalf("user enable: exit = %d; out: %s", code, out)
		}
		e.wantStatusAs(dev, "GET", "/api/me", nil, http.StatusOK, "после разблокировки")
	})

	t.Run("user_role_меняет_права_на_живом_сервере", func(t *testing.T) {
		dev := cred{"cli-developer", "pw-developer"}
		code, body := e.statusAs(dev, "POST", "/api/apps",
			strings.NewReader(`{"name":"dev-app"}`), jsonHdr)
		if !deniedAPI(t, code, body) {
			t.Fatalf("developer создал приложение: status = %d, want 403; body: %s", code, body)
		}
		if out, code := run(nil, "user", "role", "cli-developer", "maintainer"); code != 0 {
			t.Fatalf("user role: exit = %d; out: %s", code, out)
		}
		e.wantStatusAs(dev, "POST", "/api/apps",
			strings.NewReader(`{"name":"dev-app"}`), http.StatusCreated,
			"после повышения через CLI")
	})

	t.Run("user_password_гасит_старые_креды_и_сессию", func(t *testing.T) {
		dep := cred{"cli-deployer", "pw-deployer"}
		e.wantStatusAs(dep, "GET", "/api/me", nil, http.StatusOK, "до смены пароля")
		if out, code := run([]string{"APPREPO_PASSWORD=cli-new-pass"},
			"user", "password", "cli-deployer"); code != 0 {
			t.Fatalf("user password: exit = %d; out: %s", code, out)
		}
		e.wantBasicDead(dep, "user password")
		e.wantStatusAs(cred{dep.user, "cli-new-pass"}, "GET", "/api/me", nil,
			http.StatusOK, "новый пароль из CLI")
	})

	t.Run("user_delete_даёт_401", func(t *testing.T) {
		adm := cred{"cli-admin", "pw-admin"}
		e.wantStatusAs(adm, "GET", "/api/me", nil, http.StatusOK, "до удаления")
		if out, code := run(nil, "user", "delete", "cli-admin", "-yes"); code != 0 {
			t.Fatalf("user delete: exit = %d; out: %s", code, out)
		}
		e.wantBasicDead(adm, "user delete")
	})

	t.Run("user_list_не_печатает_хешей", func(t *testing.T) {
		out, code := run(nil, "user", "list")
		if code != 0 {
			t.Fatalf("user list: exit = %d; out: %s", code, out)
		}
		if strings.Contains(out, "$2a$") || strings.Contains(out, "$2b$") {
			t.Errorf("user list напечатал bcrypt-хеш: %s", out)
		}
		for _, want := range []string{"root", "cli-deployer", "deployer", "maintainer"} {
			if !strings.Contains(out, want) {
				t.Errorf("user list не содержит %q; out: %s", want, out)
			}
		}
	})

	t.Run("CLI_защищает_последнего_админа", func(t *testing.T) {
		// В БД остались админы root и cli-admin? cli-admin удалён выше,
		// значит root — последний. Ни разжаловать, ни заблокировать, ни удалить.
		for _, tc := range [][]string{
			{"user", "role", "root", "developer"},
			{"user", "disable", "root"},
			{"user", "delete", "root", "-yes"},
		} {
			out, code := run(nil, tc...)
			if code == 0 {
				t.Errorf("%v прошла на последнем админе; out: %s", tc, out)
				continue
			}
			if !strings.Contains(out, "no active administrator") {
				t.Errorf("%v: сообщение не объясняет отказ; out: %s", tc, out)
			}
		}
		// И по HTTP админ по-прежнему работает.
		e.wantStatusAs(cred{"root", "root-pass"}, "GET", "/api/users", nil,
			http.StatusOK, "последний админ цел")
	})
}
