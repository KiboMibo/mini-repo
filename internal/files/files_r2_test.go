package files

// R2-test: основное покрытие файлового хранилища (T3) по критериям приёмки
// плана docs/plans/2026-08-06-app-artifactory.md, включая краевые случаи:
// Save пустого файла, большого файла потоково (io.Reader-генератор, без
// гигантского []byte в памяти), несоответствие регистра hex-хеша, ошибка
// ридера посреди стрима.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestSaveEmptyFile(t *testing.T) {
	st := newStorage(t)
	// Пустой wantSHA256 тут не используем: проверяем и сверку хеша пустого файла
	// (регистр — верхний, сравнение регистронезависимое).
	sum, size, err := st.Save("app", "1.0.0", "empty.bin", strings.NewReader(""), strings.ToUpper(emptySHA256))
	if err != nil {
		t.Fatalf("Save empty: %v", err)
	}
	if size != 0 {
		t.Errorf("size = %d, want 0", size)
	}
	if sum != emptySHA256 {
		t.Errorf("sha256 = %q, want %q (hash of empty input)", sum, emptySHA256)
	}
	fi, err := os.Stat(st.Path("app", "1.0.0", "empty.bin"))
	if err != nil {
		t.Fatalf("stored file missing: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("stored file size = %d, want 0", fi.Size())
	}
}

// patternReader детерминированно генерирует n байт, не держа их в памяти.
type patternReader struct {
	n   int64 // сколько осталось
	off int64
}

func (p *patternReader) Read(buf []byte) (int, error) {
	if p.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(buf)) > p.n {
		buf = buf[:p.n]
	}
	for i := range buf {
		buf[i] = byte((p.off + int64(i)) * 31)
	}
	p.off += int64(len(buf))
	p.n -= int64(len(buf))
	return len(buf), nil
}

func TestSaveLargeFileStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("large-file test skipped in -short mode")
	}
	const fileSize = 128 << 20 // 128 MiB — заведомо больше любых внутренних буферов
	st := newStorage(t)

	// Ожидаемый хеш считаем тем же генератором, отдельным проходом.
	h := sha256.New()
	if _, err := io.Copy(h, &patternReader{n: fileSize}); err != nil {
		t.Fatal(err)
	}
	wantHex := hex.EncodeToString(h.Sum(nil))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	sum, size, err := st.Save("bigapp", "1.0.0", "big.bin", &patternReader{n: fileSize}, wantHex)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("Save large: %v", err)
	}
	if size != fileSize {
		t.Errorf("size = %d, want %d", size, fileSize)
	}
	if sum != wantHex {
		t.Errorf("sha256 = %q, want %q", sum, wantHex)
	}
	fi, err := os.Stat(st.Path("bigapp", "1.0.0", "big.bin"))
	if err != nil || fi.Size() != fileSize {
		t.Errorf("stored file: %v, size %d, want %d", err, fi.Size(), fileSize)
	}
	// Потоковость: суммарные аллокации за время Save должны быть на порядки
	// меньше размера файла (io.Copy работает буфером в десятки КБ).
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > fileSize/4 {
		t.Errorf("Save allocated %d bytes for a %d-byte file: not streaming", allocated, int64(fileSize))
	}
}

func TestSaveWrongHashRejectedRegardlessOfCase(t *testing.T) {
	st := newStorage(t)
	content := "payload"
	sum := sha256.Sum256([]byte(content))
	right := hex.EncodeToString(sum[:])
	// Неверный хеш: инвертируем первый символ; регистронезависимость сравнения
	// не должна пропускать по-настоящему другой хеш ни в каком регистре.
	wrong := "f" + right[1:]
	if wrong == right {
		wrong = "0" + right[1:]
	}
	for _, w := range []string{wrong, strings.ToUpper(wrong)} {
		if _, _, err := st.Save("app", "1.0.0", "f", strings.NewReader(content), w); !errors.Is(err, ErrHashMismatch) {
			t.Errorf("Save with wrong hash %q: err = %v, want ErrHashMismatch", w, err)
		}
	}
	// Верный хеш в смешанном регистре — принимается.
	mixed := strings.ToUpper(right[:32]) + right[32:]
	if _, _, err := st.Save("app", "1.0.0", "f", strings.NewReader(content), mixed); err != nil {
		t.Errorf("Save with mixed-case correct hash: %v", err)
	}
}

type failingReader struct{ after int }

func (f *failingReader) Read(buf []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("simulated read failure")
	}
	n := f.after
	if n > len(buf) {
		n = len(buf)
	}
	f.after -= n
	return n, nil
}

func TestSaveReaderErrorCleansUp(t *testing.T) {
	st := newStorage(t)
	_, _, err := st.Save("app", "1.0.0", "f", &failingReader{after: 10}, "")
	if err == nil {
		t.Fatal("Save with failing reader: want error")
	}
	if errors.Is(err, ErrHashMismatch) {
		t.Fatalf("reader failure misreported as hash mismatch: %v", err)
	}
	// Ни целевого файла, ни остатков в .tmp.
	for _, p := range entries(t, st.Root) {
		if p != filepath.Join(st.Root, ".tmp") {
			t.Errorf("leftover after failed Save: %s", p)
		}
	}
}

func TestRemoveNonexistentFails(t *testing.T) {
	st := newStorage(t)
	if err := st.Remove("app", "1.0.0", "ghost"); err == nil {
		t.Error("Remove of nonexistent file: want error, got nil")
	}
}

func TestRemovePrunesEmptyVersionDir(t *testing.T) {
	st := newStorage(t)
	if _, _, err := st.Save("app", "1.0.0", "only", strings.NewReader("x"), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("app", "1.0.0", "only"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(st.Root, "app", "1.0.0")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("empty version dir not pruned: %v", err)
	}
	// А с двумя файлами каталог остаётся.
	if _, _, err := st.Save("app", "2.0.0", "a", strings.NewReader("x"), ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Save("app", "2.0.0", "b", strings.NewReader("y"), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("app", "2.0.0", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.Path("app", "2.0.0", "b")); err != nil {
		t.Errorf("sibling file lost on Remove: %v", err)
	}
}

func TestSaveWithoutWantHashSkipsCheck(t *testing.T) {
	st := newStorage(t)
	content := "no hash provided"
	sum := sha256.Sum256([]byte(content))
	sha, size, err := st.Save("app", "1.0.0", "f", strings.NewReader(content), "")
	if err != nil {
		t.Fatalf("Save without wantSHA256: %v", err)
	}
	if sha != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %q, want %q", sha, hex.EncodeToString(sum[:]))
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
}
