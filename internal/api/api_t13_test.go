package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wantPath asserts whether a path exists on disk (T13: файлы обязаны реально
// исчезать, поэтому проверяем диск, а не только ответы API).
func wantPath(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if want && err != nil {
		t.Fatalf("%s: want present, got %v", path, err)
	}
	if !want && err == nil {
		t.Fatalf("%s: want gone, still present", path)
	}
}

// wantBody asserts a successful download of the exact bytes.
func wantBody(t *testing.T, mux *http.ServeMux, path, content string) {
	t.Helper()
	w := do(t, mux, "GET", path, "", nil)
	wantStatus(t, w, http.StatusOK)
	if got := w.Body.String(); got != content {
		t.Fatalf("%s: body = %q, want %q", path, got, content)
	}
}

func TestPatchAppRename(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "oldname")
	content := "renamed-binary"
	wantStatus(t, putVersion(t, mux, "oldname", "1.0.0", content, nil), http.StatusCreated)
	// Файл лежит под именем "{app}-{version}", каталог — под именем приложения.
	wantPath(t, filepath.Join(dir, "oldname", "1.0.0", "oldname-1.0.0"), true)

	w := do(t, mux, "PATCH", "/api/apps/oldname", `{"name":"newname","description":"d2"}`, nil)
	wantStatus(t, w, http.StatusOK)
	m := decode(t, w)
	if m["name"] != "newname" || m["description"] != "d2" {
		t.Fatalf("patch body: %s", w.Body.String())
	}
	// Тот же формат, что у GET /api/apps/{name}: со списком версий и latest.
	if m["versions"] == nil || m["latest"] == nil || m["versions_count"] != float64(1) {
		t.Fatalf("patch body is not the app-detail shape: %s", w.Body.String())
	}
	if latest, _ := m["latest"].(map[string]any); latest == nil ||
		latest["download_url"] != baseURL+"/download/newname/1.0.0" {
		t.Fatalf("latest download_url not renamed: %s", w.Body.String())
	}

	// Каталог переехал вместе со строкой в БД.
	wantPath(t, filepath.Join(dir, "oldname"), false)
	wantPath(t, filepath.Join(dir, "newname", "1.0.0", "oldname-1.0.0"), true)

	// Путь скачивания сменился: старый — 404, новый отдаёт те же байты.
	wantStatus(t, do(t, mux, "GET", "/download/oldname/1.0.0", "", nil), http.StatusNotFound)
	wantBody(t, mux, "/download/newname/1.0.0", content)
	wantBody(t, mux, "/download/newname/latest", content)
	wantErr(t, do(t, mux, "GET", "/api/apps/oldname", "", nil), http.StatusNotFound, "not_found")
	wantStatus(t, do(t, mux, "GET", "/api/apps/newname", "", nil), http.StatusOK)
}

func TestPatchAppNameTaken(t *testing.T) {
	mux, dir := newMuxDir(t)
	for _, name := range []string{"one", "two"} {
		createApp(t, mux, name)
		wantStatus(t, putVersion(t, mux, name, "1.0.0", "body-"+name, nil), http.StatusCreated)
	}

	wantErr(t, do(t, mux, "PATCH", "/api/apps/one", `{"name":"two"}`, nil),
		http.StatusConflict, "already_exists")

	// Коллизию ловит UNIQUE в БД до касания диска: оба каталога целы, обе
	// строки на месте, файлы скачиваются как прежде.
	wantPath(t, filepath.Join(dir, "one", "1.0.0", "one-1.0.0"), true)
	wantPath(t, filepath.Join(dir, "two", "1.0.0", "two-1.0.0"), true)
	wantBody(t, mux, "/download/one/1.0.0", "body-one")
	wantBody(t, mux, "/download/two/1.0.0", "body-two")
	if m := decode(t, do(t, mux, "GET", "/api/apps/one", "", nil)); m["name"] != "one" {
		t.Fatalf("app one was renamed despite the conflict")
	}
}

// TestPatchAppRenameRollback: каталог назначения уже занят посторонним файлом,
// которого нет в БД, — files.RenameApp падает, и хендлер обязан вернуть имя в
// БД обратно, иначе строка укажет на несуществующий каталог.
func TestPatchAppRenameRollback(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "app")
	wantStatus(t, putVersion(t, mux, "app", "1.0.0", "payload", nil), http.StatusCreated)
	if err := os.Mkdir(filepath.Join(dir, "squatter"), 0o700); err != nil {
		t.Fatal(err)
	}

	wantErr(t, do(t, mux, "PATCH", "/api/apps/app", `{"name":"squatter","description":"x"}`, nil),
		http.StatusConflict, "already_exists")

	// Компенсация: имя и описание вернулись, каталог не тронут, скачивание живо.
	w := do(t, mux, "GET", "/api/apps/app", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["name"] != "app" || m["description"] != "d" {
		t.Fatalf("rollback did not restore the row: %s", w.Body.String())
	}
	wantErr(t, do(t, mux, "GET", "/api/apps/squatter", "", nil), http.StatusNotFound, "not_found")
	wantPath(t, filepath.Join(dir, "app", "1.0.0", "app-1.0.0"), true)
	wantBody(t, mux, "/download/app/1.0.0", "payload")
}

func TestPatchAppFields(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")

	// Оба поля отсутствуют — не ошибка, ничего не меняется.
	for _, body := range []string{`{}`, ``} {
		w := do(t, mux, "PATCH", "/api/apps/myapp", body, nil)
		wantStatus(t, w, http.StatusOK)
		if m := decode(t, w); m["name"] != "myapp" || m["description"] != "d" {
			t.Fatalf("empty patch %q changed the app: %s", body, w.Body.String())
		}
	}

	// Только описание — имя не трогается.
	w := do(t, mux, "PATCH", "/api/apps/myapp", `{"description":"only desc"}`, nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["name"] != "myapp" || m["description"] != "only desc" {
		t.Fatalf("description-only patch: %s", w.Body.String())
	}

	// Пустое имя и прочие невалидные — 400; битый JSON — validation.
	for _, body := range []string{`{"name":""}`, `{"name":"../evil"}`, `{"name":"latest"}`} {
		wantErr(t, do(t, mux, "PATCH", "/api/apps/myapp", body, nil),
			http.StatusBadRequest, "invalid_name")
	}
	wantErr(t, do(t, mux, "PATCH", "/api/apps/myapp", `{not json`, nil),
		http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "PATCH", "/api/apps/nope", `{"description":"x"}`, nil),
		http.StatusNotFound, "not_found")
	// Переименование в собственное имя — no-op, а не 409 на самого себя.
	wantStatus(t, do(t, mux, "PATCH", "/api/apps/myapp", `{"name":"myapp"}`, nil), http.StatusOK)
}

func TestDeleteVersion(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "myapp")
	wantStatus(t, putVersion(t, mux, "myapp", "1.0.0", "keep-me", nil), http.StatusCreated)
	wantStatus(t, putVersion(t, mux, "myapp", "2.0.0", "drop-me", nil), http.StatusCreated)

	w := do(t, mux, "DELETE", "/api/apps/myapp/versions/2.0.0", "", nil)
	wantStatus(t, w, http.StatusNoContent)
	if w.Body.Len() != 0 {
		t.Fatalf("204 must have no body, got %q", w.Body.String())
	}

	// Каталог удалённой версии исчез, соседняя версия и её файл целы.
	wantPath(t, filepath.Join(dir, "myapp", "2.0.0"), false)
	wantPath(t, filepath.Join(dir, "myapp", "1.0.0", "myapp-1.0.0"), true)
	wantBody(t, mux, "/download/myapp/1.0.0", "keep-me")
	wantErr(t, do(t, mux, "GET", "/api/apps/myapp/versions/2.0.0", "", nil),
		http.StatusNotFound, "not_found")
	if m := decode(t, do(t, mux, "GET", "/api/apps/myapp", "", nil)); m["versions_count"] != float64(1) {
		t.Fatalf("versions_count = %v, want 1", m["versions_count"])
	}

	// Повторное удаление, несуществующая версия, несуществующее приложение,
	// невалидная версия.
	wantErr(t, do(t, mux, "DELETE", "/api/apps/myapp/versions/2.0.0", "", nil),
		http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "DELETE", "/api/apps/nope/versions/1.0.0", "", nil),
		http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "DELETE", "/api/apps/myapp/versions/abc", "", nil),
		http.StatusBadRequest, "invalid_version")
}

// TestDeleteLatestVersion: latest пересчитывается и когда он был максимумом
// semver, и когда был закреплён override (FK ON DELETE SET NULL снимает пин).
func TestDeleteLatestVersion(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	for _, v := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		wantStatus(t, putVersion(t, mux, "myapp", v, "c"+v, nil), http.StatusCreated)
	}

	// Auto-latest = максимум semver; после удаления — следующий максимум.
	wantStatus(t, do(t, mux, "DELETE", "/api/apps/myapp/versions/3.0.0", "", nil), http.StatusNoContent)
	w := do(t, mux, "GET", "/api/apps/myapp/latest", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["version"] != "2.0.0" {
		t.Fatalf("latest after deleting auto-latest = %v, want 2.0.0", m["version"])
	}

	// Закрепляем 1.0.0 и удаляем её: пин снимается, latest снова авто (2.0.0).
	wantStatus(t, do(t, mux, "POST", "/api/apps/myapp/latest", `{"version":"1.0.0"}`, nil), http.StatusOK)
	wantStatus(t, do(t, mux, "DELETE", "/api/apps/myapp/versions/1.0.0", "", nil), http.StatusNoContent)
	w = do(t, mux, "GET", "/api/apps/myapp/latest", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["version"] != "2.0.0" || m["is_latest"] != true {
		t.Fatalf("latest after deleting the pinned version: %s", w.Body.String())
	}

	// Удаление последней версии: latest больше нет.
	wantStatus(t, do(t, mux, "DELETE", "/api/apps/myapp/versions/2.0.0", "", nil), http.StatusNoContent)
	wantErr(t, do(t, mux, "GET", "/api/apps/myapp/latest", "", nil),
		http.StatusNotFound, "not_found")
}

func TestDeleteApp(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "doomed")
	createApp(t, mux, "keeper")
	wantStatus(t, putVersion(t, mux, "doomed", "1.0.0", "a", nil), http.StatusCreated)
	wantStatus(t, putVersion(t, mux, "doomed", "2.0.0", "b", nil), http.StatusCreated)
	wantStatus(t, putVersion(t, mux, "keeper", "1.0.0", "k", nil), http.StatusCreated)

	w := do(t, mux, "DELETE", "/api/apps/doomed", "", nil)
	wantStatus(t, w, http.StatusNoContent)
	if w.Body.Len() != 0 {
		t.Fatalf("204 must have no body, got %q", w.Body.String())
	}

	// Каталог приложения исчез целиком, вместе со всеми версиями.
	wantPath(t, filepath.Join(dir, "doomed"), false)
	wantErr(t, do(t, mux, "GET", "/api/apps/doomed", "", nil), http.StatusNotFound, "not_found")
	wantStatus(t, do(t, mux, "GET", "/download/doomed/1.0.0", "", nil), http.StatusNotFound)

	// Соседнее приложение не задето.
	wantPath(t, filepath.Join(dir, "keeper", "1.0.0", "keeper-1.0.0"), true)
	wantBody(t, mux, "/download/keeper/1.0.0", "k")

	// Удаление несуществующего — 404 (и повторное удаление тоже).
	wantErr(t, do(t, mux, "DELETE", "/api/apps/doomed", "", nil), http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "DELETE", "/api/apps/never", "", nil), http.StatusNotFound, "not_found")
}

// TestUnauthorizedMutations: новые маршруты закрыты тем же Basic Auth.
func TestUnauthorizedMutations(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "myapp")
	wantStatus(t, putVersion(t, mux, "myapp", "1.0.0", "c", nil), http.StatusCreated)

	for _, tc := range []struct{ method, path, body string }{
		{"PATCH", "/api/apps/myapp", `{"name":"other"}`},
		{"DELETE", "/api/apps/myapp", ""},
		{"DELETE", "/api/apps/myapp/versions/1.0.0", ""},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: status = %d, want 401", tc.method, tc.path, w.Code)
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s %s: missing WWW-Authenticate", tc.method, tc.path)
		}
		if m := decode(t, w); m["error"] != "unauthorized" {
			t.Fatalf("%s %s: body = %s, want unauthorized JSON", tc.method, tc.path, w.Body.String())
		}
	}

	// Ничего не изменилось: приложение, версия и файл на месте.
	wantStatus(t, do(t, mux, "GET", "/api/apps/myapp", "", nil), http.StatusOK)
	wantPath(t, filepath.Join(dir, "myapp", "1.0.0", "myapp-1.0.0"), true)
}
