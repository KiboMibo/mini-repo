package files

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T12: переименование и удаление на диске.

// seed stores one file under {app}/{version}/{name} and returns its path.
func seed(t *testing.T, st *Storage, app, version, name string) string {
	t.Helper()
	if _, _, err := st.Save(app, version, name, strings.NewReader("payload"), ""); err != nil {
		t.Fatalf("Save(%s/%s/%s): %v", app, version, name, err)
	}
	return st.Path(app, version, name)
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestRenameApp(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "old", "1.2.3", "bin")

	if err := st.RenameApp("old", "new"); err != nil {
		t.Fatalf("RenameApp: %v", err)
	}
	if exists(t, filepath.Join(st.Root, "old")) {
		t.Error("исходный каталог остался на диске")
	}
	if !exists(t, st.Path("new", "1.2.3", "bin")) {
		t.Error("файл не переехал в каталог нового имени")
	}
	// Повторное переименование в то же имя — no-op, а не ErrFileExists.
	if err := st.RenameApp("new", "new"); err != nil {
		t.Errorf("RenameApp в то же имя: %v", err)
	}
}

func TestRenameAppWithoutVersions(t *testing.T) {
	st := newStorage(t)
	// У приложения ещё нет версий — каталога нет, это не ошибка.
	if err := st.RenameApp("empty", "renamed"); err != nil {
		t.Fatalf("RenameApp без каталога: %v", err)
	}
	if got := entries(t, st.Root); len(got) != 0 {
		t.Errorf("на диске что-то создано: %v", got)
	}
}

func TestRenameAppTargetExists(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "old", "1.2.3", "bin")
	seed(t, st, "taken", "2.0.0", "bin")
	before := entries(t, st.Root)

	if err := st.RenameApp("old", "taken"); !errors.Is(err, ErrFileExists) {
		t.Fatalf("RenameApp в занятое имя: want ErrFileExists, got %v", err)
	}
	if got := entries(t, st.Root); len(got) != len(before) {
		t.Errorf("дерево изменилось: было %v, стало %v", before, got)
	}
	if !exists(t, st.Path("taken", "2.0.0", "bin")) {
		t.Error("чужой файл затёрт")
	}
}

// Пустой каталог назначения os.Rename перезаписал бы молча — тоже отказ.
func TestRenameAppTargetExistsEmptyDir(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "old", "1.2.3", "bin")
	if err := os.Mkdir(filepath.Join(st.Root, "taken"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := st.RenameApp("old", "taken"); !errors.Is(err, ErrFileExists) {
		t.Fatalf("want ErrFileExists, got %v", err)
	}
	if !exists(t, st.Path("old", "1.2.3", "bin")) {
		t.Error("исходный файл потерян")
	}
}

func TestRemoveApp(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "myapp", "1.0.0", "bin")
	seed(t, st, "myapp", "2.0.0", "bin")
	seed(t, st, "other", "1.0.0", "bin")
	// Посторонний файл в каталоге приложения тоже должен уехать.
	if err := os.WriteFile(filepath.Join(st.Root, "myapp", "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := st.RemoveApp("myapp"); err != nil {
		t.Fatalf("RemoveApp: %v", err)
	}
	if exists(t, filepath.Join(st.Root, "myapp")) {
		t.Error("каталог приложения остался на диске")
	}
	if !exists(t, st.Path("other", "1.0.0", "bin")) {
		t.Error("удалено лишнее")
	}
	// Удаление отсутствующего — не ошибка (в т.ч. повторный вызов).
	if err := st.RemoveApp("myapp"); err != nil {
		t.Errorf("повторный RemoveApp: %v", err)
	}
}

func TestRemoveVersion(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "myapp", "1.0.0", "bin")
	seed(t, st, "myapp", "2.0.0", "bin")

	if err := st.RemoveVersion("myapp", "1.0.0"); err != nil {
		t.Fatalf("RemoveVersion: %v", err)
	}
	if exists(t, filepath.Join(st.Root, "myapp", "1.0.0")) {
		t.Error("каталог версии остался на диске")
	}
	if !exists(t, st.Path("myapp", "2.0.0", "bin")) {
		t.Error("удалена не та версия")
	}
	if err := st.RemoveVersion("myapp", "3.0.0"); err != nil {
		t.Errorf("RemoveVersion отсутствующей: %v", err)
	}
}

// Версия в files обязана быть уже канонической — как в Save/Remove.
func TestRemoveVersionRequiresCanonicalVersion(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "myapp", "1.2.3", "bin")
	for _, v := range []string{"v1.2.3", "1.2", "1.2.3+"} {
		if err := st.RemoveVersion("myapp", v); err == nil {
			t.Errorf("RemoveVersion(%q): ожидалась ошибка", v)
		}
	}
	if !exists(t, st.Path("myapp", "1.2.3", "bin")) {
		t.Error("файл удалён по неканонической версии")
	}
}

func TestT12TraversalRejected(t *testing.T) {
	st := newStorage(t)
	victim := filepath.Join(filepath.Dir(st.Root), "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := []string{"../victim", "..", "a/b", "/etc", "latest", ""}

	for _, name := range bad {
		if err := st.RenameApp(name, "ok"); err == nil {
			t.Errorf("RenameApp(oldName=%q): ожидалась ошибка", name)
		}
		if err := st.RenameApp("ok", name); err == nil {
			t.Errorf("RenameApp(newName=%q): ожидалась ошибка", name)
		}
		if err := st.RemoveApp(name); err == nil {
			t.Errorf("RemoveApp(%q): ожидалась ошибка", name)
		}
		if err := st.RemoveVersion(name, "1.0.0"); err == nil {
			t.Errorf("RemoveVersion(app=%q): ожидалась ошибка", name)
		}
		if err := st.RemoveVersion("myapp", name); err == nil {
			t.Errorf("RemoveVersion(version=%q): ожидалась ошибка", name)
		}
	}
	if err := st.RemoveVersion("myapp", "../../victim"); err == nil {
		t.Error("RemoveVersion с traversal в версии: ожидалась ошибка")
	}
	if !exists(t, victim) {
		t.Fatal("каталог за пределами Root удалён — traversal сработал")
	}
	if got := entries(t, st.Root); len(got) != 0 {
		t.Errorf("отклонённые вызовы наследили: %v", got)
	}
}
