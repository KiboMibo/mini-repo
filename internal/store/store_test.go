package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Минимальный smoke-тест T2: Open + CRUD + latest. Основное покрытие — R2-test.

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestSmoke(t *testing.T) {
	s, path := openTemp(t)

	// users
	if err := s.CreateUser("alice", "hash", "admin"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.CreateUser("alice", "hash2", "admin"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate user: want ErrExists, got %v", err)
	}
	u, err := s.GetUser("alice")
	if err != nil || u == nil || u.PasswordHash != "hash" {
		t.Fatalf("GetUser: %v, %+v", err, u)
	}
	if u2, err := s.GetUser("nobody"); err != nil || u2 != nil {
		t.Fatalf("GetUser missing: want (nil,nil), got %v, %v", u2, err)
	}
	if n, _ := s.CountUsers(); n != 1 {
		t.Fatalf("CountUsers: want 1, got %d", n)
	}

	// apps
	app, err := s.CreateApp("myapp", "desc")
	if err != nil || app.Name != "myapp" {
		t.Fatalf("CreateApp: %v, %+v", err, app)
	}
	if _, err := s.CreateApp("myapp", ""); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate app: want ErrExists, got %v", err)
	}
	if a, err := s.GetApp("missing"); err != nil || a != nil {
		t.Fatalf("GetApp missing: want (nil,nil), got %v, %v", a, err)
	}
	if apps, err := s.ListApps(); err != nil || len(apps) != 1 {
		t.Fatalf("ListApps: %v", err)
	}

	// versions: semver-порядок, включая prerelease и 1.10 > 1.9
	for _, ver := range []string{"1.9.0-rc.1", "v1.9.1", "1.10.0"} {
		if _, err := s.CreateVersion(app.ID, ver, "f.bin", 3, "AB12"); err != nil {
			t.Fatalf("CreateVersion(%s): %v", ver, err)
		}
	}
	if _, err := s.CreateVersion(app.ID, "1.10.0", "f.bin", 3, "ab12"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate version: want ErrExists, got %v", err)
	}
	vs, err := s.ListVersions(app.ID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if got := []string{vs[0].Version, vs[1].Version, vs[2].Version}; got[0] != "1.10.0" || got[1] != "1.9.1" || got[2] != "1.9.0-rc.1" {
		t.Fatalf("semver order wrong: %v", got)
	}
	if vs[0].SHA256 != "ab12" {
		t.Fatalf("sha256 not lowercased: %q", vs[0].SHA256)
	}

	// latest: авто → максимум semver
	latest, err := s.LatestVersion(app.ID)
	if err != nil || latest.Version != "1.10.0" {
		t.Fatalf("LatestVersion auto: %v, %+v", err, latest)
	}
	// override
	pin, _ := s.GetVersion(app.ID, "1.9.1")
	if err := s.SetLatestOverride(app.ID, &pin.ID); err != nil {
		t.Fatalf("SetLatestOverride: %v", err)
	}
	if latest, _ = s.LatestVersion(app.ID); latest.Version != "1.9.1" {
		t.Fatalf("LatestVersion override: %+v", latest)
	}
	// override на чужую версию — ошибка
	other, _ := s.CreateApp("other", "")
	if err := s.SetLatestOverride(other.ID, &pin.ID); err == nil {
		t.Fatal("SetLatestOverride foreign version: want error")
	}
	// снять
	if err := s.SetLatestOverride(app.ID, nil); err != nil {
		t.Fatalf("clear override: %v", err)
	}
	if latest, _ = s.LatestVersion(app.ID); latest.Version != "1.10.0" {
		t.Fatalf("LatestVersion after clear: %+v", latest)
	}
	// приложение без версий → (nil, nil)
	if latest, err = s.LatestVersion(other.ID); err != nil || latest != nil {
		t.Fatalf("LatestVersion empty: want (nil,nil), got %v, %v", latest, err)
	}

	// DeleteVersion
	if err := s.DeleteVersion(pin.ID); err != nil {
		t.Fatalf("DeleteVersion: %v", err)
	}
	if v, _ := s.GetVersion(app.ID, "1.9.1"); v != nil {
		t.Fatalf("version not deleted: %+v", v)
	}

	// sessions
	token, err := s.CreateSession(u.ID, time.Hour)
	if err != nil || len(token) != 64 {
		t.Fatalf("CreateSession: %v, token %q", err, token)
	}
	sess, err := s.GetSession(token)
	if err != nil || sess == nil || sess.UserID != u.ID {
		t.Fatalf("GetSession: %v, %+v", err, sess)
	}
	// просроченная: (nil, nil) и строка удалена
	expired, _ := s.CreateSession(u.ID, -time.Minute)
	if sess, err := s.GetSession(expired); err != nil || sess != nil {
		t.Fatalf("expired session: want (nil,nil), got %v, %v", sess, err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = ?`, expired).Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired session row not deleted: n=%d err=%v", n, err)
	}
	if err := s.DeleteSession(token); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if sess, _ := s.GetSession(token); sess != nil {
		t.Fatal("session survived DeleteSession")
	}

	// повторный Open той же БД — идемпотентная схема
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if n, err := s2.CountUsers(); err != nil || n != 1 {
		t.Fatalf("reopen CountUsers: %d, %v", n, err)
	}
}

// TestOpenFilePermissions: файл БД (и wal/shm, если созданы) — 0600, чужим
// локальным пользователям токены сессий и хеши паролей не видны.
func TestOpenFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue // wal/shm может не существовать — это нормально
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s: mode = %o, want 600", p, got)
		}
	}
}

// F6: инцидент на боевом развёртывании — каталог БД остался read-only
// (не попал в systemd ReadWritePaths), а в логе было только «unable to open
// database file» без имени файла. Ошибка обязана называть путь.
func TestOpenErrorNamesPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("под root права каталога не мешают записи")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) // иначе t.TempDir не уберёт за собой
	path := filepath.Join(dir, "apprepo.db")
	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatalf("Open в каталоге 0500 должен возвращать ошибку")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %q; в тексте нет пути %s", err, path)
	}
}
