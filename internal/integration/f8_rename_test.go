package integration

// F8: приложение, названное как сосед по data-dir (файл БД и его -wal/-shm),
// не должно уметь унести этот файл через переименование. Находка N1 из
// docs/plans/reviews/app-artifactory-R5-sec-round2.md: до правки
// PATCH /api/apps/apprepo.db {"name":"moved"} отвечал 200 и переносил боевой
// файл БД, после чего следующий store.Open падал с disk I/O error.

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"apprepo/internal/store"
)

// TestRenameAppNamedLikeTheDatabaseFile: и API, и UI отвечают 409, файл БД и
// его спутники остаются на месте, имя в БД откатывается, а сервис после
// отказа по-прежнему открывается на том же каталоге.
func TestRenameAppNamedLikeTheDatabaseFile(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	if filepath.Dir(e.cfg.DBPath) != e.dataDir {
		t.Skip("test assumes the default layout (DB inside the data dir)")
	}
	c := e.uiClient()
	e.login(c, "/")

	dbName := filepath.Base(e.cfg.DBPath)
	for _, victim := range []string{dbName, dbName + "-wal", dbName + "-shm"} {
		t.Run(victim, func(t *testing.T) {
			target := filepath.Join(e.dataDir, victim)
			if _, err := os.Lstat(target); err != nil {
				t.Skipf("%s does not exist in this run, nothing to steal", target)
			}
			e.createApp(victim) // имя с точкой и дефисом проходит naming

			// Оба входа в files.RenameApp: JSON API и форма UI.
			for _, tc := range []struct {
				name    string
				newName string
				do      func(newName string) *http.Response
			}{
				{"api", "moved-api-" + victim, func(newName string) *http.Response {
					b, err := jsonBody(map[string]string{"name": newName})
					if err != nil {
						t.Fatalf("marshal: %v", err)
					}
					return e.renameViaAPI(victim, b)
				}},
				{"ui", "moved-ui-" + victim, func(newName string) *http.Response {
					return e.renameViaUI(c, victim, newName, "")
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					resp := tc.do(tc.newName)
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusConflict {
						t.Fatalf("rename %q -> %q via %s: status = %d, want 409; body: %s",
							victim, tc.newName, tc.name, resp.StatusCode, readBody(t, resp))
					}
					mustExist(t, target, "the file the app is named after, after a refused rename")
					mustNotExist(t, filepath.Join(e.dataDir, tc.newName),
						"the rename destination")
					// Компенсация: имя строки откачено на прежнее.
					if status, _ := e.appJSONOf(victim); status != http.StatusOK {
						t.Errorf("GET /api/apps/%s after the refused rename: status = %d, want 200",
							victim, status)
					}
					if status, _ := e.appJSONOf(tc.newName); status != http.StatusNotFound {
						t.Errorf("the app is reachable under the refused new name %q: status = %d",
							tc.newName, status)
					}
				})
			}

			// Прибираем за собой: строка мешала бы следующему подтесту только
			// именем, но и она не должна утащить файл с диска.
			resp := e.deleteAppAPI(victim)
			deleted := resp.StatusCode
			resp.Body.Close()
			if deleted != http.StatusConflict {
				t.Errorf("DELETE /api/apps/%s: status = %d, want 409 (F7 guard)", victim, deleted)
			}
			mustExist(t, target, "the file the app is named after, after a refused delete")
		})
	}

	// Главное последствие N1: осиротевшие -wal/-shm ломали следующий запуск.
	mustExist(t, e.cfg.DBPath, "database file after every refused rename")
	st, err := store.Open(e.cfg.DBPath)
	if err != nil {
		t.Fatalf("store.Open on the same data dir after the refused renames: %v", err)
	}
	if _, err := st.ListApps(); err != nil {
		t.Errorf("ListApps on the reopened database: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	e.assertNoDanglingRows()
}
