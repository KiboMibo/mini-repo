package integration

// Обновление боевой установки до волны 6: БД со схемой ДО T18 (users без
// role/disabled), в ней живой пользователь, приложение, версия и файл на
// диске. Критерий: «обновление на сервере не сломает прод» — проверяется не
// через store, а сквозь HTTP на собранном app.New.

import (
	"database/sql"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/auth"
)

const (
	legacyUser    = "olduser"
	legacyPass    = "old-password"
	legacyApp     = "legacy-app"
	legacyVersion = "1.2.3"
	legacyFile    = "legacy-bin"
)

var legacyPayload = []byte("payload written before wave 6")

// preWave6Schema — схема ровно та, что лежала в internal/store/schema.sql на
// merge-base с develop: users без role и disabled. Остальные таблицы волна 6
// не трогала, но они нужны, чтобы приложение и версия «приехали» из прошлого.
const preWave6Schema = `
CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE apps (
  id                         INTEGER PRIMARY KEY,
  name                       TEXT NOT NULL UNIQUE,
  description                TEXT NOT NULL DEFAULT '',
  latest_override_version_id INTEGER REFERENCES versions(id) ON DELETE SET NULL,
  created_at                 TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE versions (
  id         INTEGER PRIMARY KEY,
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  version    TEXT NOT NULL,
  filename   TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256     TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, version)
);
CREATE TABLE sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);
`

// seedPreWave6 builds a data directory as a pre-wave-6 installation would have
// left it: БД старой схемы с пользователем, приложением и версией + файл на
// диске по тому же пути, который считает files.Storage.
func seedPreWave6(t *testing.T, cfg config0) {
	t.Helper()
	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(legacyPass)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	db, err := sql.Open("sqlite3", "file:"+cfg.dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(preWave6Schema); err != nil {
		t.Fatalf("схема до T18: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		legacyUser, hash); err != nil {
		t.Fatalf("вставка пользователя: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO apps (id, name, description) VALUES (1, ?, 'built before wave 6')`,
		legacyApp); err != nil {
		t.Fatalf("вставка приложения: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO versions (app_id, version, filename, size_bytes, sha256)
		 VALUES (1, ?, ?, ?, ?)`,
		legacyVersion, legacyFile, int64(len(legacyPayload)), sha256hex(legacyPayload)); err != nil {
		t.Fatalf("вставка версии: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dir := filepath.Join(cfg.dataDir, legacyApp, legacyVersion)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyFile), legacyPayload, 0o600); err != nil {
		t.Fatal(err)
	}
}

// config0 — минимум путей, чтобы засеять каталог до того, как появится env.
type config0 struct{ dataDir, dbPath string }

// TestUpgradeOfPreWave6Installation: сервис, работавший до волны 6, после
// обновления бинарника поднимается на той же БД, старый пользователь входит и
// получает роль admin со всеми правами, данные и файлы на месте. Повторный
// запуск (перезапуск сервиса) ничего не ломает.
func TestUpgradeOfPreWave6Installation(t *testing.T) {
	root := t.TempDir()
	cfg := cfgAt(root, defaultMaxUpload)
	seedPreWave6(t, config0{dataDir: cfg.DataDir, dbPath: cfg.DBPath})

	legacy := cred{legacyUser, legacyPass}

	// Два прогона на одном каталоге: первый — обновление, второй — обычный
	// перезапуск уже мигрированной установки. Миграция обязана быть идемпотентной.
	for _, pass := range []string{"после обновления", "после перезапуска"} {
		t.Run(pass, func(t *testing.T) {
			e := bootEnv(t, cfg)

			t.Run("старый_пароль_всё_ещё_пускает", func(t *testing.T) {
				code, body := e.statusAs(legacy, "GET", "/api/me", nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET /api/me: status = %d, want 200; body: %s", code, body)
				}
				if !strings.Contains(body, `"role":"admin"`) {
					t.Errorf("роль после миграции: %s, want admin", body)
				}
			})

			t.Run("у_мигрированной_учётки_все_права", func(t *testing.T) {
				// По одному маршруту на каждое право волны 6.
				e.wantStatusAs(legacy, "GET", "/api/apps", nil, http.StatusOK, "PermRead")
				e.wantStatusAs(legacy, "GET", "/api/users", nil, http.StatusOK, "PermUserAdmin")
				e.wantStatusAs(legacy, "PUT",
					"/api/apps/"+legacyApp+"/versions/9.9."+pass9(pass)+
						"?filename="+legacyApp+"-9.9."+pass9(pass)+"&platform="+testPlatform,
					strings.NewReader("fresh"), http.StatusCreated, "PermVersion")
				e.wantStatusAs(legacy, "POST", "/api/apps",
					strings.NewReader(`{"name":"new-`+pass9(pass)+`"}`),
					http.StatusCreated, "PermApp")
				// PermUI: страница интерфейса открывается, а не отдаёт отказ.
				c := e.mustLoginAs(legacy)
				if code, body := e.uiStatus(c, "/"); code != http.StatusOK {
					t.Errorf("GET / в UI: status = %d, want 200 (PermUI); body: %s", code, body)
				}
			})

			t.Run("старое_приложение_и_версия_на_месте", func(t *testing.T) {
				code, body := e.statusAs(legacy, "GET", "/api/apps/"+legacyApp, nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET /api/apps/%s: status = %d, want 200; body: %s", legacyApp, code, body)
				}
				if !strings.Contains(body, "built before wave 6") {
					t.Errorf("описание приложения потеряно: %s", body)
				}
				code, body = e.statusAs(legacy, "GET", "/api/apps/"+legacyApp+"/versions/"+legacyVersion, nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET версии: status = %d, want 200; body: %s", code, body)
				}
				if !strings.Contains(body, sha256hex(legacyPayload)) {
					t.Errorf("sha256 версии не совпал: %s", body)
				}
			})

			t.Run("файл_скачивается", func(t *testing.T) {
				resp := e.apiAs(legacy, "GET", "/download/"+legacyApp+"/"+legacyVersion, nil, nil)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("download: status = %d, want 200; body: %s",
						resp.StatusCode, readBody(t, resp))
				}
				if got := readBody(t, resp); got != string(legacyPayload) {
					t.Errorf("содержимое файла = %q, want %q", got, legacyPayload)
				}
			})

			t.Run("учётка_не_заблокирована_и_видна_в_списке", func(t *testing.T) {
				code, body := e.statusAs(legacy, "GET", "/api/users", nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET /api/users: status = %d; body: %s", code, body)
				}
				if !strings.Contains(body, `"username":"`+legacyUser+`"`) {
					t.Fatalf("мигрированного пользователя нет в списке: %s", body)
				}
				if !strings.Contains(body, `"disabled":false`) {
					t.Errorf("мигрированная учётка пришла заблокированной: %s", body)
				}
			})
		})
	}
}

// pass9 даёт уникальный суффикс на прогон, чтобы создание приложения и версии
// во втором прогоне не упиралось в результат первого (данные-то те же).
func pass9(pass string) string {
	if strings.Contains(pass, "перезапуска") {
		return "2"
	}
	return "1"
}

// TestPartiallyMigratedDatabase: обновление могло прерваться между двумя
// ALTER TABLE (падение процесса, kill -9 при рестарте юнита). Следующий запуск
// обязан дойти до конца, а не упасть на «колонка уже существует».
func TestPartiallyMigratedDatabase(t *testing.T) {
	root := t.TempDir()
	cfg := cfgAt(root, defaultMaxUpload)
	seedPreWave6(t, config0{dataDir: cfg.DataDir, dbPath: cfg.DBPath})

	db, err := sql.Open("sqlite3", "file:"+cfg.DBPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// Ровно первый шаг миграции — role есть, disabled ещё нет.
	if _, err := db.Exec(
		`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'`); err != nil {
		t.Fatalf("половина миграции: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	e := bootEnv(t, cfg)
	code, body := e.statusAs(cred{legacyUser, legacyPass}, "GET", "/api/me", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/me после половинной миграции: status = %d, want 200; body: %s", code, body)
	}
	if !strings.Contains(body, `"role":"admin"`) {
		t.Errorf("роль после дозагрузки миграции: %s, want admin", body)
	}
	// Колонка disabled дописана — блокировка работает.
	e.wantStatusAs(cred{legacyUser, legacyPass}, "GET", "/api/users", nil,
		http.StatusOK, "PermUserAdmin")
	if u := e.mustStoreUser(legacyUser); u.Disabled {
		t.Error("дозагруженная колонка disabled выставлена в true")
	}
}

// TestSessionIssuedBeforeUpgradeStillWorks: пользователь, залогиненный в
// браузере до обновления, не должен обнаружить себя выброшенным — строка
// сессии живёт в БД и обязана пережить миграцию.
func TestSessionIssuedBeforeUpgradeStillWorks(t *testing.T) {
	root := t.TempDir()
	cfg := cfgAt(root, defaultMaxUpload)
	seedPreWave6(t, config0{dataDir: cfg.DataDir, dbPath: cfg.DBPath})

	const oldToken = "0123456789abcdef0123456789abcdef"
	db, err := sql.Open("sqlite3", "file:"+cfg.DBPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (token, user_id, expires_at)
		 VALUES (?, 1, datetime('now','+7 days'))`, oldToken); err != nil {
		t.Fatalf("вставка сессии: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	e := bootEnv(t, cfg)
	c := e.uiClient()
	u, _ := url.Parse(e.srv.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: auth.SessionCookie, Value: oldToken}})

	code, body := e.uiStatus(c, "/")
	if code != http.StatusOK {
		t.Fatalf("сессия, выданная до обновления: status = %d, want 200; body: %s", code, body)
	}
	if !strings.Contains(body, legacyApp) {
		t.Errorf("страница не показывает старое приложение %q; body: %s", legacyApp, body)
	}
}
