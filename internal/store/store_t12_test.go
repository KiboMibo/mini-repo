package store

import (
	"errors"
	"strings"
	"testing"
)

// T12: переименование и удаление приложений/версий.

// mustApp/mustVersion — из store_r2_test.go.

func TestUpdateApp(t *testing.T) {
	s, _ := openTemp(t)
	a := mustApp(t, s, "old")

	if err := s.UpdateApp(a.ID, "new", "новое описание"); err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	got, err := s.GetApp("new")
	if err != nil || got == nil {
		t.Fatalf("GetApp(new): %v, %v", got, err)
	}
	if got.ID != a.ID || got.Description != "новое описание" {
		t.Errorf("после UpdateApp: %+v", got)
	}
	if old, err := s.GetApp("old"); err != nil || old != nil {
		t.Errorf("старое имя всё ещё резолвится: %v, %v", old, err)
	}
}

func TestUpdateAppNameTaken(t *testing.T) {
	s, _ := openTemp(t)
	a := mustApp(t, s, "one")
	mustApp(t, s, "two")

	if err := s.UpdateApp(a.ID, "two", "desc"); !errors.Is(err, ErrExists) {
		t.Fatalf("переименование в занятое имя: want ErrExists, got %v", err)
	}
	// Ничего не поменялось: ни имя, ни описание.
	got, err := s.GetApp("one")
	if err != nil || got == nil || got.Description != "" {
		t.Errorf("приложение изменено при отказе: %+v, %v", got, err)
	}
}

func TestUpdateAppRejectsInvalidName(t *testing.T) {
	s, _ := openTemp(t)
	a := mustApp(t, s, "myapp")
	for _, name := range []string{"../evil", "a/b", "", "latest", strings.Repeat("x", 65)} {
		if err := s.UpdateApp(a.ID, name, ""); err == nil {
			t.Errorf("UpdateApp(%q): ожидалась ошибка валидации", name)
		}
	}
	if got, _ := s.GetApp("myapp"); got == nil {
		t.Error("приложение переименовано невалидным именем")
	}
}

func TestUpdateAppMissing(t *testing.T) {
	s, _ := openTemp(t)
	if err := s.UpdateApp(4242, "ghost", ""); err == nil {
		t.Fatal("UpdateApp несуществующего id: ожидалась ошибка")
	}
}

// Удаление версии, закреплённой как latest: FK ON DELETE SET NULL снимает пин,
// latest пересчитывается по semver.
func TestDeleteVersionClearsOverride(t *testing.T) {
	s, _ := openTemp(t)
	a := mustApp(t, s, "myapp")
	v1 := mustVersion(t, s, a.ID, "1.0.0")
	mustVersion(t, s, a.ID, "2.0.0")

	if err := s.SetLatestOverride(a.ID, &v1.ID); err != nil {
		t.Fatalf("SetLatestOverride: %v", err)
	}
	if latest, err := s.LatestVersion(a.ID); err != nil || latest == nil || latest.Version != "1.0.0" {
		t.Fatalf("пин не применился: %v, %v", latest, err)
	}

	if err := s.DeleteVersion(v1.ID); err != nil {
		t.Fatalf("DeleteVersion: %v", err)
	}
	got, err := s.GetApp("myapp")
	if err != nil || got == nil || got.LatestOverrideVersionID != nil {
		t.Fatalf("пин не снят: %+v, %v", got, err)
	}
	latest, err := s.LatestVersion(a.ID)
	if err != nil || latest == nil || latest.Version != "2.0.0" {
		t.Fatalf("latest не пересчитался: %v, %v", latest, err)
	}
	if vs, err := s.ListVersions(a.ID); err != nil || len(vs) != 1 {
		t.Fatalf("ListVersions: %v, %v", vs, err)
	}
}

// Удаление последней версии оставляет приложение без версий — валидное состояние.
func TestDeleteLastVersion(t *testing.T) {
	s, _ := openTemp(t)
	a := mustApp(t, s, "myapp")
	v := mustVersion(t, s, a.ID, "1.0.0")

	if err := s.DeleteVersion(v.ID); err != nil {
		t.Fatalf("DeleteVersion: %v", err)
	}
	if got, err := s.GetApp("myapp"); err != nil || got == nil {
		t.Fatalf("приложение исчезло вместе с версией: %v, %v", got, err)
	}
	if latest, err := s.LatestVersion(a.ID); err != nil || latest != nil {
		t.Fatalf("LatestVersion без версий: want (nil,nil), got %v, %v", latest, err)
	}
	// Повторное удаление — не ошибка.
	if err := s.DeleteVersion(v.ID); err != nil {
		t.Errorf("повторный DeleteVersion: %v", err)
	}
}

func TestDeleteApp(t *testing.T) {
	s, _ := openTemp(t)
	a := mustApp(t, s, "myapp")
	v1 := mustVersion(t, s, a.ID, "1.0.0")
	mustVersion(t, s, a.ID, "2.0.0")
	if err := s.SetLatestOverride(a.ID, &v1.ID); err != nil {
		t.Fatalf("SetLatestOverride: %v", err)
	}
	other := mustApp(t, s, "other")
	mustVersion(t, s, other.ID, "1.0.0")

	if err := s.DeleteApp(a.ID); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if got, err := s.GetApp("myapp"); err != nil || got != nil {
		t.Errorf("приложение осталось: %v, %v", got, err)
	}
	// Строки версий должны уйти каскадом (иначе PRAGMA foreign_keys выключен).
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM versions WHERE app_id = ?`, a.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("осиротевших строк версий: %d, want 0", n)
	}
	if vs, err := s.ListVersions(other.ID); err != nil || len(vs) != 1 {
		t.Errorf("задето соседнее приложение: %v, %v", vs, err)
	}
	// Удаление несуществующего — не ошибка.
	if err := s.DeleteApp(a.ID); err != nil {
		t.Errorf("повторный DeleteApp: %v", err)
	}
}
