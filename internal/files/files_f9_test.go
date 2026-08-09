package files

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F9 (N3 круга 3 R5-sec): пакет защищал по типу цели удаление (F7) и перенос
// (F8), но не запись — у Save проверки не было вовсе, поэтому статически
// подложенного симлинка на месте {Root}/{app} хватало, чтобы файл создался за
// пределами Root, без всякой гонки.

// TestSaveRefusesSymlinkedAppDir: симлинк на каталог снаружи Root — запись
// отклоняется, за пределами Root ничего не появляется.
func TestSaveRefusesSymlinkedAppDir(t *testing.T) {
	st := newStorage(t)
	outside := t.TempDir()
	link := filepath.Join(st.Root, "sneaky")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("симлинки недоступны в этой ФС: %v", err)
	}

	_, _, err := st.Save("sneaky", "1.0.0", "bin", strings.NewReader("payload"), "")
	if !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("Save по симлинку = %v, want ErrNotDirectory", err)
	}
	if got := entries(t, outside); len(got) != 0 {
		t.Errorf("за пределами Root создано: %v", got)
	}
	if !exists(t, link) {
		t.Error("симлинк тронут")
	}
}

// TestSaveRefusesSymlinkedVersionDir: тот же рубеж на втором уровне —
// {Root}/{app}/{version}, как в RemoveVersion.
func TestSaveRefusesSymlinkedVersionDir(t *testing.T) {
	st := newStorage(t)
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(st.Root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(st.Root, "app", "1.0.0")); err != nil {
		t.Skipf("симлинки недоступны в этой ФС: %v", err)
	}

	_, _, err := st.Save("app", "1.0.0", "bin", strings.NewReader("payload"), "")
	if !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("Save в симлинк-версию = %v, want ErrNotDirectory", err)
	}
	if got := entries(t, outside); len(got) != 0 {
		t.Errorf("за пределами Root создано: %v", got)
	}
}

// TestSaveRefusesNeighbourFileName: имя приложения совпало с соседом по
// data-dir (файл БД) — ErrNotDirectory вместо безымянной ошибки ФС, соседний
// файл байт-в-байт цел.
func TestSaveRefusesNeighbourFileName(t *testing.T) {
	st := newStorage(t)
	const content = "SQLite format 3\x00"
	for _, name := range []string{"apprepo.db", "apprepo.db-wal", "apprepo.db-shm"} {
		p := filepath.Join(st.Root, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := st.Save(name, "1.0.0", "bin", strings.NewReader("payload"), "")
		if !errors.Is(err, ErrNotDirectory) {
			t.Errorf("Save(%q) = %v, want ErrNotDirectory", name, err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != content {
			t.Errorf("сосед %s изменён: %q, %v", name, got, err)
		}
	}
}

// TestSaveGuardKeepsNormalCases: рубеж не сломал штатную запись — ни первую
// (каталогов ещё нет), ни вторую версию в уже существующий каталог.
func TestSaveGuardKeepsNormalCases(t *testing.T) {
	st := newStorage(t)
	seed(t, st, "app", "1.0.0", "bin")
	seed(t, st, "app", "1.1.0", "bin")
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if !exists(t, st.Path("app", v, "bin")) {
			t.Errorf("версия %s не записана", v)
		}
	}
}
