package files

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// F7: рубеж «удаляем только собственные каталоги». Root — это data-dir, в
// котором лежат и файлы БД (apprepo.db, -wal, -shm), и .tmp; их имена проходят
// naming.ValidateAppName, поэтому решает тип цели, а не её имя.

// TestRemoveAppRefusesPlainFile: под именем приложения лежит обычный файл
// (как файл SQLite рядом с каталогами приложений) — он должен уцелеть.
func TestRemoveAppRefusesPlainFile(t *testing.T) {
	st := newStorage(t)
	for _, name := range []string{"apprepo.db", "apprepo.db-wal", "apprepo.db-shm"} {
		p := filepath.Join(st.Root, name)
		if err := os.WriteFile(p, []byte("SQLite format 3"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := st.RemoveApp(name); !errors.Is(err, ErrNotDirectory) {
			t.Errorf("RemoveApp(%q) = %v, want ErrNotDirectory", name, err)
		}
		if !exists(t, p) {
			t.Fatalf("RemoveApp(%q) удалил файл %s", name, p)
		}
	}
}

// TestRemoveAppRefusesSymlink: симлинк на каталог снаружи Root не удаляется —
// ни сам линк, ни его цель.
func TestRemoveAppRefusesSymlink(t *testing.T) {
	st := newStorage(t)
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.MkdirAll(filepath.Join(outside, "1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(st.Root, "sneaky")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("симлинки недоступны в этой ФС: %v", err)
	}

	if err := st.RemoveApp("sneaky"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("RemoveApp по симлинку = %v, want ErrNotDirectory", err)
	}
	if !exists(t, link) {
		t.Error("симлинк удалён")
	}
	if !exists(t, outside) {
		t.Fatal("цель симлинка удалена")
	}
}

// TestRemoveVersionRefusesSymlinkedAppDir: os.RemoveAll резолвит родительские
// компоненты пути, поэтому симлинк на месте {Root}/{app} без проверки увёл бы
// удаление наружу Root.
func TestRemoveVersionRefusesSymlinkedAppDir(t *testing.T) {
	st := newStorage(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "1.0.0")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(st.Root, "sneaky")); err != nil {
		t.Skipf("симлинки недоступны в этой ФС: %v", err)
	}

	if err := st.RemoveVersion("sneaky", "1.0.0"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("RemoveVersion через симлинк = %v, want ErrNotDirectory", err)
	}
	if !exists(t, target) {
		t.Fatalf("каталог %s снаружи Root удалён через симлинк", target)
	}
}

// TestRemoveVersionRefusesPlainFileAsVersion: сам каталог версии тоже обязан
// быть каталогом.
func TestRemoveVersionRefusesPlainFileAsVersion(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "myapp", "1.2.3", "bin")
	stray := filepath.Join(st.Root, "myapp", "2.0.0")
	if err := os.WriteFile(stray, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := st.RemoveVersion("myapp", "2.0.0"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("RemoveVersion по файлу = %v, want ErrNotDirectory", err)
	}
	if !exists(t, stray) {
		t.Error("файл на месте каталога версии удалён")
	}
}

// TestRemoveMissingIsNotAnError: идемпотентность сохраняется — отсутствие цели
// (в том числе отсутствие каталога приложения) по-прежнему не ошибка.
func TestRemoveMissingIsNotAnError(t *testing.T) {
	st := newStorage(t)
	if err := st.RemoveApp("nosuchapp"); err != nil {
		t.Errorf("RemoveApp отсутствующего: %v", err)
	}
	if err := st.RemoveVersion("nosuchapp", "1.0.0"); err != nil {
		t.Errorf("RemoveVersion без каталога приложения: %v", err)
	}
	seed(t, st, "myapp", "1.2.3", "bin")
	if err := st.RemoveVersion("myapp", "9.9.9"); err != nil {
		t.Errorf("RemoveVersion отсутствующей версии: %v", err)
	}
	if !exists(t, st.Path("myapp", "1.2.3", "bin")) {
		t.Error("no-op удалил чужой файл")
	}
}

// TestRemoveNormalDirectoriesStillWorks: рубеж не мешает обычной работе.
func TestRemoveNormalDirectoriesStillWorks(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "myapp", "1.2.3", "bin")
	seed(t, st, "myapp", "2.0.0", "bin")

	if err := st.RemoveVersion("myapp", "1.2.3"); err != nil {
		t.Fatalf("RemoveVersion: %v", err)
	}
	if exists(t, filepath.Join(st.Root, "myapp", "1.2.3")) {
		t.Error("каталог версии остался")
	}
	if err := st.RemoveApp("myapp"); err != nil {
		t.Fatalf("RemoveApp: %v", err)
	}
	if exists(t, filepath.Join(st.Root, "myapp")) {
		t.Error("каталог приложения остался")
	}
}
