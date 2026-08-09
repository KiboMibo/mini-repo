//go:build unix

package platform

// Отдельный файл ради тега сборки: syscall.Mkfifo есть только на unix, а сервис
// и живёт только там (systemd-юнит в deploy/).

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestDetectFIFO: FIFO в data-dir не должен подвешивать разбор. Открытие без
// O_NONBLOCK ждёт писателя вечно, и рубеж «только регулярный файл» до дела не
// доходил — app.New на такой data-dir не возвращался никогда (R8-sec S3).
func TestDetectFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("Mkfifo недоступен: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if got, err := Detect(path); got != "" || err != nil {
			t.Errorf("Detect(fifo) = %q, %v; want \"\", nil", got, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Detect(fifo) не вернулся за 5 с — открытие блокируется")
	}
}
