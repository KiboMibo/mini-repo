package files

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// F8: тот же рубеж, что F7 поставила на удаление, — на переименовании.
// os.Rename переносит объект любого типа, поэтому источник обязан быть
// настоящим каталогом приложения: иначе приложение с именем соседа по
// data-dir (apprepo.db, -wal, -shm) унесло бы файл БД под другое имя.

// TestRenameAppRefusesPlainFileSource: под именем приложения лежит обычный
// файл — он должен остаться на месте, а не переехать.
func TestRenameAppRefusesPlainFileSource(t *testing.T) {
	st := newStorage(t)
	for _, name := range []string{"apprepo.db", "apprepo.db-wal", "apprepo.db-shm"} {
		src := filepath.Join(st.Root, name)
		if err := os.WriteFile(src, []byte("SQLite format 3"), 0o600); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(st.Root, "moved-"+name)

		if err := st.RenameApp(name, "moved-"+name); !errors.Is(err, ErrNotDirectory) {
			t.Errorf("RenameApp(%q) = %v, want ErrNotDirectory", name, err)
		}
		if !exists(t, src) {
			t.Fatalf("RenameApp(%q) унёс файл %s", name, src)
		}
		if exists(t, dst) {
			t.Errorf("RenameApp(%q) создал %s", name, dst)
		}
	}
}

// TestRenameAppRefusesSymlinkedSource: симлинк на каталог снаружи Root не
// переезжает — ни сам линк, ни его цель не трогаются.
func TestRenameAppRefusesSymlinkedSource(t *testing.T) {
	st := newStorage(t)
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.MkdirAll(filepath.Join(outside, "1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(st.Root, "sneaky")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("симлинки недоступны в этой ФС: %v", err)
	}

	if err := st.RenameApp("sneaky", "moved"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("RenameApp по симлинку = %v, want ErrNotDirectory", err)
	}
	if !exists(t, link) {
		t.Error("симлинк переехал")
	}
	if !exists(t, filepath.Join(outside, "1.0.0")) {
		t.Fatal("каталог снаружи Root тронут")
	}
	if exists(t, filepath.Join(st.Root, "moved")) {
		t.Error("создан каталог назначения")
	}
}

// TestRenameAppGuardKeepsNormalCases: рубеж не сломал штатную работу —
// отсутствие источника по-прежнему не ошибка, настоящий каталог переезжает.
func TestRenameAppGuardKeepsNormalCases(t *testing.T) {
	st := newStorage(t)
	if err := st.RenameApp("nosuchapp", "renamed"); err != nil {
		t.Errorf("RenameApp без каталога: %v", err)
	}
	if got := entries(t, st.Root); len(got) != 0 {
		t.Errorf("на диске что-то создано: %v", got)
	}

	seed(t, st, "old", "1.2.3", "bin")
	if err := st.RenameApp("old", "new"); err != nil {
		t.Fatalf("RenameApp настоящего каталога: %v", err)
	}
	if !exists(t, st.Path("new", "1.2.3", "bin")) {
		t.Error("файл не переехал в каталог нового имени")
	}
}
