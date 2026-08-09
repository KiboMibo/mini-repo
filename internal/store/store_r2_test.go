package store

// R2-test: основное покрытие слоя хранения (T2) по критериям приёмки плана
// docs/plans/2026-08-06-app-artifactory.md, включая краевые случаи:
// semver-сортировка с prerelease, override на чужую/несуществующую версию,
// гонка двух CreateVersion одной версии (UNIQUE).

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func mustApp(t *testing.T, s *Store, name string) *App {
	t.Helper()
	app, err := s.CreateApp(name, "")
	if err != nil {
		t.Fatalf("CreateApp(%q): %v", name, err)
	}
	return app
}

func mustVersion(t *testing.T, s *Store, appID int64, ver string) *Version {
	t.Helper()
	v, err := s.CreateVersion(appID, ver, "f.bin", 1, "ab")
	if err != nil {
		t.Fatalf("CreateVersion(%q): %v", ver, err)
	}
	return v
}

func semver_desc_order_includes_prerelease_below_release(t *testing.T, s *Store) {
	app := mustApp(t, s, "ordering")
	// Вставляем в перемешанном порядке, чтобы порядок вставки не совпадал с ожидаемым.
	input := []string{"1.0.0", "1.0.0-alpha", "1.10.0", "1.0.0-rc.1", "1.2.0", "1.0.0-alpha.1", "1.9.1"}
	for _, ver := range input {
		mustVersion(t, s, app.ID, ver)
	}
	want := []string{"1.10.0", "1.9.1", "1.2.0", "1.0.0", "1.0.0-rc.1", "1.0.0-alpha.1", "1.0.0-alpha"}
	vs, err := s.ListVersions(app.ID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(vs) != len(want) {
		t.Fatalf("ListVersions len = %d, want %d", len(vs), len(want))
	}
	for i, w := range want {
		if vs[i].Version != w {
			t.Errorf("ListVersions[%d] = %q, want %q (full: %v)", i, vs[i].Version, w, versionsOf(vs))
		}
	}
	// latest без override — максимум semver: релиз 1.10.0, а не какой-либо prerelease
	latest, err := s.LatestVersion(app.ID)
	if err != nil || latest == nil || latest.Version != "1.10.0" {
		t.Fatalf("LatestVersion = %+v, %v; want 1.10.0", latest, err)
	}
}

func prerelease_of_higher_major_wins_over_lower_release(t *testing.T, s *Store) {
	// По semver 2.0.0-beta > 1.10.0 — prerelease понижает только относительно
	// релиза той же версии. Фиксируем это поведение как контрактное.
	app := mustApp(t, s, "premajor")
	mustVersion(t, s, app.ID, "1.10.0")
	mustVersion(t, s, app.ID, "2.0.0-beta")
	latest, err := s.LatestVersion(app.ID)
	if err != nil || latest == nil || latest.Version != "2.0.0-beta" {
		t.Fatalf("LatestVersion = %+v, %v; want 2.0.0-beta", latest, err)
	}
}

func versionsOf(vs []*Version) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Version
	}
	return out
}

func concurrent_create_version_same_version_exactly_one_wins(t *testing.T, s *Store) {
	app := mustApp(t, s, "race")
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = s.CreateVersion(app.ID, "3.0.0", "f.bin", 1, "ab")
		}(i)
	}
	close(start)
	wg.Wait()
	var ok, dup int
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrExists):
			dup++
		default:
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
	if ok != 1 || dup != n-1 {
		t.Errorf("successes = %d, ErrExists = %d; want 1 and %d", ok, dup, n-1)
	}
	vs, err := s.ListVersions(app.ID)
	if err != nil || len(vs) != 1 {
		t.Errorf("after race: %d rows, err %v; want exactly 1", len(vs), err)
	}
}

func override_validation_rejects_foreign_and_missing(t *testing.T, s *Store) {
	app := mustApp(t, s, "ovr-a")
	other := mustApp(t, s, "ovr-b")
	v := mustVersion(t, s, app.ID, "1.0.0")

	if err := s.SetLatestOverride(other.ID, &v.ID); err == nil {
		t.Error("override to foreign app's version: want error, got nil")
	}
	if got, _ := s.GetApp(other.Name); got.LatestOverrideVersionID != nil {
		t.Error("foreign override was written despite error")
	}
	missing := v.ID + 100500
	if err := s.SetLatestOverride(app.ID, &missing); err == nil {
		t.Error("override to nonexistent version id: want error, got nil")
	}
	if err := s.SetLatestOverride(app.ID+100500, nil); err == nil {
		t.Error("clear override on nonexistent app: want error, got nil")
	}
}

func delete_of_pinned_version_clears_override(t *testing.T, s *Store) {
	// FK latest_override_version_id ... ON DELETE SET NULL + PRAGMA foreign_keys:
	// удаление закреплённой версии снимает закрепление, latest возвращается к max semver.
	app := mustApp(t, s, "pin-del")
	mustVersion(t, s, app.ID, "2.0.0")
	pin := mustVersion(t, s, app.ID, "1.0.0")
	if err := s.SetLatestOverride(app.ID, &pin.ID); err != nil {
		t.Fatalf("SetLatestOverride: %v", err)
	}
	if err := s.DeleteVersion(pin.ID); err != nil {
		t.Fatalf("DeleteVersion: %v", err)
	}
	got, err := s.GetApp("pin-del")
	if err != nil || got == nil {
		t.Fatalf("GetApp: %v", err)
	}
	if got.LatestOverrideVersionID != nil {
		t.Errorf("override not cleared after deleting pinned version: %v", *got.LatestOverrideVersionID)
	}
	latest, err := s.LatestVersion(app.ID)
	if err != nil || latest == nil || latest.Version != "2.0.0" {
		t.Fatalf("LatestVersion after pinned delete = %+v, %v; want 2.0.0", latest, err)
	}
}

func create_version_rejects_invalid_semver_and_canonicalizes_v_prefix(t *testing.T, s *Store) {
	app := mustApp(t, s, "vers-valid")
	for _, bad := range []string{"", "abc", "1.2", "1.2.3.4", "latest"} {
		if _, err := s.CreateVersion(app.ID, bad, "f", 1, "ab"); err == nil {
			t.Errorf("CreateVersion(%q): want error, got nil", bad)
		}
	}
	if vs, _ := s.ListVersions(app.ID); len(vs) != 0 {
		t.Errorf("invalid versions were inserted: %v", versionsOf(vs))
	}
	created, err := s.CreateVersion(app.ID, "v1.2.3", "f", 1, "AB12CD")
	if err != nil {
		t.Fatalf("CreateVersion(v1.2.3): %v", err)
	}
	if created.Version != "1.2.3" {
		t.Errorf("stored version = %q, want canonical \"1.2.3\"", created.Version)
	}
	if created.SHA256 != "ab12cd" {
		t.Errorf("stored sha256 = %q, want lowercased \"ab12cd\"", created.SHA256)
	}
	// GetVersion тоже принимает префикс v и находит каноническую запись
	got, err := s.GetVersion(app.ID, "v1.2.3")
	if err != nil || got == nil || got.ID != created.ID {
		t.Errorf("GetVersion(v1.2.3) = %+v, %v; want id %d", got, err, created.ID)
	}
	if miss, err := s.GetVersion(app.ID, "9.9.9"); err != nil || miss != nil {
		t.Errorf("GetVersion(missing) = %+v, %v; want (nil,nil)", miss, err)
	}
}

func same_version_allowed_in_different_apps(t *testing.T, s *Store) {
	a := mustApp(t, s, "uniq-a")
	b := mustApp(t, s, "uniq-b")
	mustVersion(t, s, a.ID, "1.0.0")
	if _, err := s.CreateVersion(b.ID, "1.0.0", "f", 1, "ab"); err != nil {
		t.Errorf("same version in another app: %v; UNIQUE must be per (app_id, version)", err)
	}
}

func session_tokens_are_unique_64_hex(t *testing.T, s *Store) {
	if err := s.CreateUser("sess-user", "h", "admin"); err != nil {
		t.Fatal(err)
	}
	u, _ := s.GetUser("sess-user")
	t1, err1 := s.CreateSession(u.ID, time.Hour)
	t2, err2 := s.CreateSession(u.ID, time.Hour)
	if err1 != nil || err2 != nil {
		t.Fatalf("CreateSession: %v, %v", err1, err2)
	}
	if len(t1) != 64 || len(t2) != 64 {
		t.Errorf("token lengths %d, %d; want 64 hex chars", len(t1), len(t2))
	}
	if t1 == t2 {
		t.Error("two sessions got the same token")
	}
}

// TestStoreR2 гоняет все сценарии на одной временной БД: подтесты используют
// разные имена приложений и не пересекаются по данным.
func TestStoreR2(t *testing.T) {
	s, _ := openTemp(t)
	t.Run("semver_desc_order_includes_prerelease_below_release", func(t *testing.T) { semver_desc_order_includes_prerelease_below_release(t, s) })
	t.Run("prerelease_of_higher_major_wins_over_lower_release", func(t *testing.T) { prerelease_of_higher_major_wins_over_lower_release(t, s) })
	t.Run("concurrent_create_version_same_version_exactly_one_wins", func(t *testing.T) { concurrent_create_version_same_version_exactly_one_wins(t, s) })
	t.Run("override_validation_rejects_foreign_and_missing", func(t *testing.T) { override_validation_rejects_foreign_and_missing(t, s) })
	t.Run("delete_of_pinned_version_clears_override", func(t *testing.T) { delete_of_pinned_version_clears_override(t, s) })
	t.Run("create_version_rejects_invalid_semver_and_canonicalizes_v_prefix", func(t *testing.T) { create_version_rejects_invalid_semver_and_canonicalizes_v_prefix(t, s) })
	t.Run("same_version_allowed_in_different_apps", func(t *testing.T) { same_version_allowed_in_different_apps(t, s) })
	t.Run("session_tokens_are_unique_64_hex", func(t *testing.T) { session_tokens_are_unique_64_hex(t, s) })
}
