//go:build unix

package app

// Отдельный файл ради тега сборки: syscall.Mkfifo есть только на unix, а сервис
// и живёт только там (systemd-юнит в deploy/).

import (
	"syscall"
	"testing"
	"time"

	"apprepo/internal/files"
)

// TestNewStartsWithFifoInDataDir: FIFO на месте файла версии не должен
// подвешивать старт. До F21 platform.Detect открывал путь без O_NONBLOCK и
// ядро блокировало open до появления писателя — app.New не возвращался никогда,
// а с Restart=on-failure это ещё и крэш-луп (R8-sec S3).
func TestNewStartsWithFifoInDataDir(t *testing.T) {
	dir := t.TempDir()
	st, _ := newApp(t, dir)
	fst := &files.Storage{Root: dir}
	seed(t, st, fst, "app", "1.0.0", "bin", nil) // строка есть, файла нет
	path := fst.Path("app", "1.0.0", "bin")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("Mkfifo недоступен: %v", err)
	}
	st.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		st2, _ := newApp(t, dir)
		if p := platformOf(t, st2, "app", "1.0.0"); p != "" {
			t.Errorf("платформа FIFO = %q, want \"\"", p)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("app.New не вернулся за 10 с — старт висит на FIFO")
	}
}
