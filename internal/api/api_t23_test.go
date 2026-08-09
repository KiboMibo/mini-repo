package api_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T23: ?filename= стал обязательным. Дефолт «{app}-{version}» убран — он
// молча отдавал многофайловый релиз без расширения, и скачанный архив система
// не опознавала. Отсутствие параметра и негодное имя — разные коды, чтобы в
// логе CI «не передал» не сливалось с «передал мусор».

// wantMissingFilename проверяет отказ целиком: код, HTTP-статус и то, что в
// тексте есть всё, ради чего он писался, — «обязателен», пример запроса и
// причина (прежний дефолт без расширения).
func wantMissingFilename(t *testing.T, mux *http.ServeMux, path string) {
	t.Helper()
	w := do(t, mux, "PUT", path, "payload", nil)
	wantErr(t, w, http.StatusBadRequest, "filename_required")
	msg, _ := decode(t, w)["message"].(string)
	for _, want := range []string{
		"?filename=",       // какой параметр
		"required",         // что с ним не так
		"-X PUT",           // пример правильного запроса
		"myapp-1.0.0",      // прежний дефолт, он же основа примера
		".tar.gz",          // расширение — ради чего всё затевалось
		"cannot recognise", // почему дефолта больше нет
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message не содержит %q; message = %q", want, msg)
		}
	}
}

func TestPutVersionRequiresFilename(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "myapp")

	t.Run("missing", func(t *testing.T) {
		wantMissingFilename(t, mux, "/api/apps/myapp/versions/1.0.0")
	})
	t.Run("empty", func(t *testing.T) {
		wantMissingFilename(t, mux, "/api/apps/myapp/versions/1.0.0?filename=")
	})

	// Версия не создана и на диске ничего не появилось: отказ стоит до чтения
	// тела, каталога версии быть не должно.
	wantErr(t, do(t, mux, "GET", "/api/apps/myapp/versions/1.0.0", "", nil),
		http.StatusNotFound, "not_found")
	wantPath(t, filepath.Join(dir, "myapp", "1.0.0"), false)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() == "myapp" {
				t.Errorf("каталог приложения создан отказанной загрузкой: %s", e.Name())
			}
		}
	}

	// Негодное имя — прежний код, отличимый от «не передал».
	wantErr(t, do(t, mux, "PUT", "/api/apps/myapp/versions/1.0.0?filename=..", "payload", nil),
		http.StatusBadRequest, "invalid_filename")

	// Валидное имя — 201, как раньше (тело текстовое, платформа по нему не
	// определяется, поэтому ?platform= обязателен — T25).
	wantStatus(t, do(t, mux, "PUT", "/api/apps/myapp/versions/1.0.0?filename=myapp-1.0.0&platform=any",
		"payload", nil), http.StatusCreated)
}

// TestPutVersionArchiveFilename — ради чего задача и делалась: имя с двойным
// расширением проходит валидацию и приезжает обратно в Content-Disposition.
func TestPutVersionArchiveFilename(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")

	const name = "myapp-1.0.0.tar.gz"
	w := do(t, mux, "PUT", "/api/apps/myapp/versions/1.0.0?filename="+name+"&platform=any",
		"archive-bytes", nil)
	wantStatus(t, w, http.StatusCreated)
	if got := decode(t, w)["filename"]; got != name {
		t.Fatalf("filename = %v, want %s", got, name)
	}

	w = do(t, mux, "GET", "/download/myapp/1.0.0", "", nil)
	wantStatus(t, w, http.StatusOK)
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, name) {
		t.Fatalf("Content-Disposition = %q, want it to carry %s", cd, name)
	}
}
