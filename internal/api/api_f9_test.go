package api_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F9 (N3 круга 3 R5-sec): загрузка версии в приложение, чьё имя совпало с
// соседом по data-dir (файл БД и его -wal/-shm), отвечала 500 — оператор не
// отличал детерминированную коллизию имени от настоящей аварии. Теперь на
// записи стоит тот же рубеж по типу цели, что у удаления (F7) и переноса
// (F8), и ответ — 409, как у них.

func TestPutVersionIntoAppNamedLikeTheDatabaseFileIs409(t *testing.T) {
	mux, dir := newMuxDir(t)
	dbPath := filepath.Join(dir, "apprepo.db")

	for _, victim := range []string{"apprepo.db", "apprepo.db-wal"} {
		t.Run(victim, func(t *testing.T) {
			target := filepath.Join(dir, victim)
			if _, err := os.Lstat(target); err != nil {
				t.Skipf("%s не существует в этом прогоне: %v", target, err)
			}
			createApp(t, mux, victim) // точка и дефис проходят naming
			// Снимок берём после записи строки в БД: между ним и загрузкой
			// SQLite только читает, поэтому байты обязаны совпасть.
			before, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}

			w := putVersion(t, mux, victim, "1.0.0", "payload", nil)
			wantErr(t, w, http.StatusConflict, "already_exists")
			// Инвариант: путь ФС уходит только в серверный лог.
			if strings.Contains(w.Body.String(), dir) {
				t.Errorf("путь data-dir утёк в тело ответа: %s", w.Body.String())
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("файл %s изменён загрузкой (err=%v)", target, err)
			}
			// Строки версии тоже не появилось: файл пишется до вставки в БД.
			wantStatus(t, do(t, mux, "GET", "/api/apps/"+victim+"/versions/1.0.0", "", nil),
				http.StatusNotFound)
		})
	}

	// Главное последствие: БД пережила отказы и по-прежнему обслуживает запросы.
	wantPath(t, dbPath, true)
	wantStatus(t, do(t, mux, "GET", "/api/apps", "", nil), http.StatusOK)

	// Штатная загрузка не задета.
	createApp(t, mux, "normal")
	wantStatus(t, putVersion(t, mux, "normal", "1.0.0", "payload", nil), http.StatusCreated)
	wantBody(t, mux, "/download/normal/1.0.0", "payload")
}
