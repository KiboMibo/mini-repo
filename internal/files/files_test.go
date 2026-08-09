package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStorage(t *testing.T) *Storage {
	t.Helper()
	return &Storage{Root: t.TempDir()}
}

// entries returns all paths under root, to assert the FS was left untouched.
func entries(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != root {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSaveOK(t *testing.T) {
	st := newStorage(t)
	content := "hello binary"
	want := sha256.Sum256([]byte(content))
	wantHex := hex.EncodeToString(want[:])

	// Uppercase client hash must be accepted (case-insensitive compare).
	sum, size, err := st.Save("myapp", "1.2.3", "myapp-linux", strings.NewReader(content), strings.ToUpper(wantHex))
	if err != nil {
		t.Fatal(err)
	}
	if sum != wantHex {
		t.Errorf("sha256 = %q, want %q", sum, wantHex)
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
	got, err := os.ReadFile(st.Path("myapp", "1.2.3", "myapp-linux"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("stored content = %q", got)
	}
}

func TestSaveHashMismatch(t *testing.T) {
	st := newStorage(t)
	_, _, err := st.Save("myapp", "1.0.0", "f", strings.NewReader("data"), strings.Repeat("0", 64))
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
	// Only the empty .tmp dir may remain: no file, no temp leftovers.
	for _, p := range entries(t, st.Root) {
		if p != filepath.Join(st.Root, ".tmp") {
			t.Errorf("leftover %s", p)
		}
	}
}

func TestSaveTraversalRejected(t *testing.T) {
	st := newStorage(t)
	for _, tc := range [][3]string{
		{"../evil", "1.0.0", "f"},
		{"app", "1.0.0/../..", "f"},
		{"app", "v1.0.0", "f"}, // non-canonical version
		{"app", "1.0.0", "a/../b"},
	} {
		if _, _, err := st.Save(tc[0], tc[1], tc[2], strings.NewReader("x"), ""); err == nil {
			t.Errorf("Save(%q,%q,%q): expected error", tc[0], tc[1], tc[2])
		}
	}
	if got := entries(t, st.Root); len(got) != 0 {
		t.Errorf("FS touched: %v", got)
	}
}

func TestSaveNoOverwrite(t *testing.T) {
	st := newStorage(t)
	if _, _, err := st.Save("app", "1.0.0", "f", strings.NewReader("original"), ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Save("app", "1.0.0", "f", strings.NewReader("evil"), ""); !errors.Is(err, ErrFileExists) {
		t.Fatalf("second Save: err = %v, want ErrFileExists", err)
	}
	got, _ := os.ReadFile(st.Path("app", "1.0.0", "f"))
	if string(got) != "original" {
		t.Errorf("original overwritten: %q", got)
	}
}

func TestRemove(t *testing.T) {
	st := newStorage(t)
	if _, _, err := st.Save("app", "1.0.0", "f", strings.NewReader("x"), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("app", "1.0.0", "f"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.Path("app", "1.0.0", "f")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file still exists: %v", err)
	}
	if err := st.Remove("app", "../evil", "f"); err == nil {
		t.Error("Remove with traversal: expected error")
	}
}

// raceReader создаёт dst на первом Read — имитирует победителя гонки,
// опубликовавшего файл после Stat-проверки Save, но до публикации (TOCTOU).
type raceReader struct {
	t       *testing.T
	dst     string
	content string
	done    bool
}

func (r *raceReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	if err := os.MkdirAll(filepath.Dir(r.dst), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.dst, []byte("winner"), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return copy(p, r.content), nil
}

// TestSaveRaceLoserGetsErrFileExists: dst появляется во время стриминга (после
// Stat-fast-path) — Save обязан вернуть ErrFileExists, не тронув файл
// победителя и подчистив свой temp.
func TestSaveRaceLoserGetsErrFileExists(t *testing.T) {
	st := newStorage(t)
	dst := st.Path("app", "1.0.0", "bin")
	_, _, err := st.Save("app", "1.0.0", "bin", &raceReader{t: t, dst: dst, content: "loser"}, "")
	if !errors.Is(err, ErrFileExists) {
		t.Fatalf("Save: err = %v, want ErrFileExists", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "winner" {
		t.Fatalf("winner's file touched: %q, %v", got, err)
	}
	tmp, err := os.ReadDir(filepath.Join(st.Root, ".tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmp) != 0 {
		t.Errorf("temp file leaked: %v", tmp)
	}
}
