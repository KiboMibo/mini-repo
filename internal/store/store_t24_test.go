package store

// T24: платформа версии — колонка platform, её миграция для старых БД и
// SetVersionPlatform. Определение платформы по файлу — в internal/platform,
// backfill старых версий — в internal/app.

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionPlatform(t *testing.T) {
	s, _ := openTemp(t)
	app := mustApp(t, s, "myapp")
	v := mustVersion(t, s, app.ID, "1.0.0")

	// Новая версия приезжает без платформы: заливка её не знает.
	if v.Platform != "" {
		t.Errorf("new version Platform = %q, want empty", v.Platform)
	}

	if err := s.SetVersionPlatform(v.ID, "Linux/AMD64"); err != nil {
		t.Fatalf("SetVersionPlatform: %v", err)
	}
	// В БД лежит канонический вид, а не то, что прислали.
	got, err := s.GetVersion(app.ID, "1.0.0")
	if err != nil || got == nil {
		t.Fatalf("GetVersion: %v, %v", got, err)
	}
	if got.Platform != "linux/amd64" {
		t.Errorf("Platform = %q, want linux/amd64", got.Platform)
	}

	// Платформа видна на всех путях чтения версии, а не только в GetVersion.
	list, err := s.ListVersions(app.ID)
	if err != nil || len(list) != 1 || list[0].Platform != "linux/amd64" {
		t.Errorf("ListVersions platform = %+v, %v", list, err)
	}
	if err := s.SetLatestOverride(app.ID, &v.ID); err != nil {
		t.Fatal(err)
	}
	if latest, err := s.LatestVersion(app.ID); err != nil || latest.Platform != "linux/amd64" {
		t.Errorf("LatestVersion platform = %+v, %v", latest, err)
	}

	// Сброс пустой строкой разрешён.
	if err := s.SetVersionPlatform(v.ID, ""); err != nil {
		t.Fatalf("SetVersionPlatform(\"\"): %v", err)
	}
	if got, _ := s.GetVersion(app.ID, "1.0.0"); got.Platform != "" {
		t.Errorf("Platform after reset = %q, want empty", got.Platform)
	}

	// "any" — тоже допустимое значение (архив, не зависящий от платформы).
	if err := s.SetVersionPlatform(v.ID, "any"); err != nil {
		t.Fatalf("SetVersionPlatform(any): %v", err)
	}
	if got, _ := s.GetVersion(app.ID, "1.0.0"); got.Platform != "any" {
		t.Errorf("Platform = %q, want any", got.Platform)
	}

	// Мусор до БД не доходит и прежнее значение не затирает.
	if err := s.SetVersionPlatform(v.ID, "amd64"); err == nil {
		t.Error("SetVersionPlatform(\"amd64\"): want an error")
	}
	if got, _ := s.GetVersion(app.ID, "1.0.0"); got.Platform != "any" {
		t.Errorf("Platform after a refused write = %q, want any", got.Platform)
	}

	// Несуществующая версия — ошибка, а не тихий успех (как у SetLatestOverride).
	if err := s.SetVersionPlatform(v.ID+1000, "linux/amd64"); err == nil {
		t.Error("SetVersionPlatform on a missing version: want an error")
	}
}

// TestMigratePreT24DB: БД, созданная кодом до T24 (versions без platform),
// открывается новым Open, версии остаются на месте и получают пустую платформу.
func TestMigratePreT24DB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Схема versions ровно та, что была в schema.sql до T24.
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE apps (
		  id                         INTEGER PRIMARY KEY,
		  name                       TEXT NOT NULL UNIQUE,
		  description                TEXT NOT NULL DEFAULT '',
		  latest_override_version_id INTEGER,
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
		INSERT INTO apps (id, name) VALUES (1, 'legacy');
		INSERT INTO versions (app_id, version, filename, size_bytes, sha256)
		  VALUES (1, '1.2.3', 'legacy-1.2.3.bin', 42, 'deadbeef');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Дважды: миграция обязана быть идемпотентной.
	for _, pass := range []string{"first open", "reopen"} {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("%s: Open: %v", pass, err)
		}
		v, err := s.GetVersion(1, "1.2.3")
		if err != nil || v == nil {
			t.Fatalf("%s: GetVersion = %v, %v", pass, v, err)
		}
		if v.Filename != "legacy-1.2.3.bin" || v.SizeBytes != 42 || v.SHA256 != "deadbeef" {
			t.Errorf("%s: version data lost: %+v", pass, v)
		}
		if v.Platform != "" {
			t.Errorf("%s: Platform = %q, want empty (unknown until backfill)", pass, v.Platform)
		}
		// Мигрированная таблица должна принимать новые вставки.
		if _, err := s.CreateVersion(1, "2.0.0-"+strings.ReplaceAll(pass, " ", "-"), "f.bin", 1, "aa"); err != nil {
			t.Errorf("%s: CreateVersion after migration: %v", pass, err)
		}
		s.Close()
	}

	// Проставленное в мигрированной таблице значение переоткрытие не сбросило.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.GetVersion(1, "1.2.3")
	if err := s.SetVersionPlatform(v.ID, "linux/arm64"); err != nil {
		t.Fatalf("SetVersionPlatform after migration: %v", err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, _ := s.GetVersion(1, "1.2.3"); v == nil || v.Platform != "linux/arm64" {
		t.Errorf("platform lost on reopen: %+v", v)
	}
}
