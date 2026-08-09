package web_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F9 (N3 круга 3 R5-sec): UI-загрузка в приложение, чьё имя совпало с соседом
// по data-dir (файл БД), отвечала 500. Тот же рубеж по типу цели, что у
// удаления и переименования, теперь стоит и на записи — ответ 409, файл БД цел.
func TestUploadIntoAppNamedLikeTheDatabaseFileIs409(t *testing.T) {
	e := newEnv(t)
	dbName := "test.db" // как в newEnv: store.Open({root}/test.db)
	for _, victim := range []string{dbName, dbName + "-wal"} {
		t.Run(victim, func(t *testing.T) {
			target := filepath.Join(e.root, victim)
			if _, err := os.Lstat(target); err != nil {
				t.Skipf("%s не существует в этом прогоне: %v", target, err)
			}
			if _, err := e.st.CreateApp(victim, ""); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}

			body, ctype := multipartBody(t, map[string]string{
				"csrf_token": csrfTok, "version": "1.0.0",
			}, "bin", []byte("payload"))
			rec := e.do(t, "POST", "/apps/"+victim+"/versions", ctype, body, true)
			if rec.Code != http.StatusConflict {
				t.Fatalf("code = %d, want 409; body: %s", rec.Code, rec.Body.String())
			}
			// Инвариант: путь ФС уходит только в серверный лог.
			if strings.Contains(rec.Body.String(), e.root) {
				t.Errorf("путь data-dir утёк в HTML: %s", rec.Body.String())
			}
			if after, err := os.ReadFile(target); err != nil || !bytes.Equal(before, after) {
				t.Errorf("файл %s изменён загрузкой (err=%v)", target, err)
			}
		})
	}
}
