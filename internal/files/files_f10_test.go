package files

// Двухфазная загрузка и замок по имени приложения (задача F10). Prepare ничего
// не создаёт под {Root}/{app} — каталог появляется только в Commit, под
// замком и после проверки вызывающего; отказ проверки не оставляет мусора.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// tempEntries lists what is left in the storage scratch dir.
func tempEntries(t *testing.T, st *Storage) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(st.Root, ".tmp"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("ReadDir .tmp: %v", err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestPrepareCreatesNothingUnderApp: пока тело льётся, каталога приложения не
// существует — именно поэтому переименование в этот момент не оставляет на
// диске лишнего каталога со старым именем.
func TestPrepareCreatesNothingUnderApp(t *testing.T) {
	st := newStorage(t)
	u, err := st.Prepare("app", "1.0.0", "bin", strings.NewReader("payload"), "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(st.Root, "app")); !os.IsNotExist(err) {
		t.Fatalf("Prepare created %s/app before Commit (err = %v)", st.Root, err)
	}
	if u.Size != int64(len("payload")) {
		t.Errorf("Size = %d, want %d", u.Size, len("payload"))
	}
	if err := u.Commit(nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := os.Stat(st.Path("app", "1.0.0", "bin")); err != nil {
		t.Fatalf("file not published: %v", err)
	}
	if left := tempEntries(t, st); len(left) != 0 {
		t.Errorf("temp files left after Commit: %v", left)
	}
}

// TestCommitCheckRefusesAndCleansUp: проверка вызывающего (приложение
// переименовали или удалили) отменяет публикацию — ошибка возвращается как
// есть, временный файл убран, каталог приложения не создан.
func TestCommitCheckRefusesAndCleansUp(t *testing.T) {
	st := newStorage(t)
	u, err := st.Prepare("app", "1.0.0", "bin", strings.NewReader("payload"), "")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	sentinel := errors.New("app was renamed")
	if err := u.Commit(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Commit err = %v, want %v", err, sentinel)
	}
	if _, err := os.Lstat(filepath.Join(st.Root, "app")); !os.IsNotExist(err) {
		t.Errorf("refused Commit created %s/app (err = %v)", st.Root, err)
	}
	if left := tempEntries(t, st); len(left) != 0 {
		t.Errorf("temp files left after a refused Commit: %v", left)
	}
}

// TestCommitAndRenameAreSerialized: публикация и перенос каталога того же
// приложения не выполняются одновременно. Смысл — прогон под -race и
// отсутствие взаимной блокировки (RenameApp берёт оба имени).
func TestCommitAndRenameAreSerialized(t *testing.T) {
	st := newStorage(t)
	if _, _, err := st.Save("app", "1.0.0", "bin", strings.NewReader("first"), ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		version := fmt.Sprintf("2.%d.0", i)
		u, err := st.Prepare("app", version, "bin", strings.NewReader("payload"), "")
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		wg.Add(2)
		go func() { defer wg.Done(); u.Commit(nil) }()
		go func() {
			// Туда и обратно: к следующей итерации каталог снова "app",
			// независимо от того, кто выиграл гонку.
			defer wg.Done()
			if err := st.RenameApp("app", "moved"); err == nil {
				st.RenameApp("moved", "app")
			}
		}()
		wg.Wait()
	}
	if left := tempEntries(t, st); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}
