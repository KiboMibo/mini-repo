package integration

// Права/защита, гонки и итоговый инвариант хранилища для волны 5.

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewAPIRoutesRequireBasicAuth: новые маршруты API без Basic Auth отвечают
// 401 и контрактным JSON-объектом ошибки, а не выполняют операцию.
func TestNewAPIRoutesRequireBasicAuth(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("guarded")
	content := e.seed("guarded", "1.0.0")

	for _, tc := range []struct{ method, path string }{
		{"PATCH", "/api/apps/guarded"},
		{"DELETE", "/api/apps/guarded"},
		{"DELETE", "/api/apps/guarded/versions/1.0.0"},
	} {
		t.Run(tc.method+"_"+strings.ReplaceAll(tc.path, "/", "_"), func(t *testing.T) {
			resp := e.anon(tc.method, tc.path)
			wantJSONError(t, resp, http.StatusUnauthorized, "unauthorized")
		})
	}

	// Ничего не произошло: приложение, версия и файл на месте.
	if status, _ := e.appJSONOf("guarded"); status != http.StatusOK {
		t.Errorf("app was modified by unauthenticated requests: status = %d", status)
	}
	if got := e.mustDownload("guarded", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("file was touched by unauthenticated requests")
	}
	e.assertNoDanglingRows()
}

// TestNewUIPostsRequireSession: новые UI-POST без сессии редиректят на логин
// и ничего не меняют.
func TestNewUIPostsRequireSession(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("uiguard")
	content := e.seed("uiguard", "1.0.0")
	anon := e.uiClient() // с cookie jar, но без логина

	for _, tc := range []struct {
		name string
		path string
		form url.Values
	}{
		{"edit", "/apps/uiguard/edit", url.Values{"name": {"stolen"}}},
		{"delete_app", "/apps/uiguard/delete", url.Values{"confirm": {"uiguard"}}},
		{"delete_version", "/apps/uiguard/versions/1.0.0/delete", url.Values{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.uiPost(anon, tc.path, tc.form)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("POST %s without a session: status = %d, want 303", tc.path, resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
				t.Errorf("POST %s without a session: Location = %q, want /login…", tc.path, loc)
			}
		})
	}

	if status, _ := e.appJSONOf("uiguard"); status != http.StatusOK {
		t.Errorf("app changed by session-less POSTs: status = %d", status)
	}
	if got := e.mustDownload("uiguard", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("file changed by session-less POSTs")
	}
	e.assertNoDanglingRows()
}

// TestNewUIPostsRequireCSRF: с валидной сессией, но без CSRF-токена — 403 и
// никаких изменений.
func TestNewUIPostsRequireCSRF(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("csrfguard")
	content := e.seed("csrfguard", "1.0.0")
	e.uiPageBody(c, "/apps/csrfguard", http.StatusOK)

	for _, tc := range []struct {
		name string
		path string
		form url.Values
	}{
		{"edit_no_token", "/apps/csrfguard/edit", url.Values{"name": {"stolen"}}},
		{"edit_wrong_token", "/apps/csrfguard/edit", url.Values{"name": {"stolen"}, "csrf_token": {"deadbeef"}}},
		{"delete_app_no_token", "/apps/csrfguard/delete", url.Values{"confirm": {"csrfguard"}}},
		{"delete_version_no_token", "/apps/csrfguard/versions/1.0.0/delete", url.Values{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.uiPost(c, tc.path, tc.form)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("POST %s without a valid CSRF token: status = %d, want 403",
					tc.path, resp.StatusCode)
			}
		})
	}

	if status, _ := e.appJSONOf("csrfguard"); status != http.StatusOK {
		t.Errorf("app changed by CSRF-less POSTs: status = %d", status)
	}
	if got := e.versionNamesOf("csrfguard"); len(got) != 1 {
		t.Errorf("versions = %v, want the single seeded one", got)
	}
	if got := e.mustDownload("csrfguard", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("file changed by CSRF-less POSTs")
	}
	e.assertNoDanglingRows()
}

// TestDeleteAppUIRequiresExactConfirm: несовпадающий confirm ничего не удаляет —
// ни строки в БД, ни файлы на диске.
func TestDeleteAppUIRequiresExactConfirm(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("confirmme")
	content := e.seed("confirmme", "1.0.0")
	e.uiPageBody(c, "/apps/confirmme", http.StatusOK)

	for _, bad := range []string{"", "confirm", "CONFIRMME", " confirmme", "confirmme "} {
		t.Run("confirm_"+url.PathEscape(bad), func(t *testing.T) {
			resp := e.deleteAppUI(c, "confirmme", bad)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("delete with confirm=%q: status = %d, want 400", bad, resp.StatusCode)
			}
			if status, _ := e.appJSONOf("confirmme"); status != http.StatusOK {
				t.Fatalf("app was deleted despite confirm=%q", bad)
			}
			mustExist(t, e.versionDir("confirmme", "1.0.0"), "version dir after a refused delete")
		})
	}

	if got := e.mustDownload("confirmme", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("file changed after refused deletes")
	}

	// Точное совпадение — удаляет.
	resp := e.deleteAppUI(c, "confirmme", "confirmme")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete with the exact confirm: status = %d, want 303", resp.StatusCode)
	}
	mustNotExist(t, e.appDir("confirmme"), "app dir after a confirmed delete")
}

// TestConcurrentDeleteAndDownloadDoesNotPanic: параллельные удаление версии и
// скачивание её же не должны валить сервер. Допустимы 200 (успели до
// удаления / читаем уже отвязанный inode), 404 (строки нет) и 500
// (строка есть, файл уже удалён) — но не паника и не обрыв соединения.
func TestConcurrentDeleteAndDownloadDoesNotPanic(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("racy")
	e.seed("racy", "1.0.0")

	const readers = 24
	var wg sync.WaitGroup
	statuses := make([]int, readers)
	start := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req, err := http.NewRequest("GET", e.srv.URL+"/download/racy/1.0.0", nil)
			if err != nil {
				statuses[i] = -1
				return
			}
			req.SetBasicAuth(testUser, testPass)
			resp, err := e.srv.Client().Do(req)
			if err != nil {
				statuses[i] = -1
				return
			}
			defer resp.Body.Close()
			// Тело обязательно вычитывается: обрыв на середине выдачи файла
			// проявился бы именно здесь.
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				statuses[i] = -2
				return
			}
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		resp := e.deleteVersionAPI("racy", "1.0.0")
		resp.Body.Close()
	}()
	close(start)
	wg.Wait()

	counts := map[int]int{}
	for _, s := range statuses {
		counts[s]++
		switch s {
		case http.StatusOK, http.StatusNotFound, http.StatusInternalServerError:
		case -1:
			t.Errorf("a concurrent download failed at the transport level (server died?)")
		case -2:
			t.Errorf("a concurrent download was truncated mid-body")
		default:
			t.Errorf("unexpected download status during a concurrent delete: %d", s)
		}
	}
	t.Logf("concurrent delete+download statuses: %v", counts)

	// Сервер жив и отвечает после гонки.
	resp := e.api("GET", "/healthz", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz after the race: status = %d, want 200", resp.StatusCode)
	}
	if status, _ := e.appJSONOf("racy"); status != http.StatusOK {
		t.Errorf("app is broken after the race: status = %d", status)
	}
	mustNotExist(t, e.versionDir("racy", "1.0.0"), "version dir after the race")
	e.assertNoDanglingRows()
}

// TestConcurrentRenameAndUploadObserved фиксирует ФАКТИЧЕСКОЕ поведение гонки
// «переименование + загрузка» — исполнители волны отметили её как известную
// шероховатость, поэтому тест ничего не требует, а только протоколирует
// исход и проверяет, что сервис остаётся работоспособным.
func TestConcurrentRenameAndUploadObserved(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("shifting")
	e.seed("shifting", "1.0.0") // каталог уже существует — переименование реально двигает файлы

	payload := payloadFor("shifting", "2.0.0")
	var wg sync.WaitGroup
	start := make(chan struct{})
	var uploadStatus, renameStatus int

	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		resp := e.putVersion("shifting", "2.0.0", "", payload, "")
		defer resp.Body.Close()
		uploadStatus = resp.StatusCode
	}()
	go func() {
		defer wg.Done()
		<-start
		resp := e.renameViaAPI("shifting", `{"name":"shifted"}`)
		defer resp.Body.Close()
		renameStatus = resp.StatusCode
	}()
	close(start)
	wg.Wait()

	name := "shifting"
	if renameStatus == http.StatusOK {
		name = "shifted"
	}
	t.Logf("observed: upload status = %d, rename status = %d, app now named %q",
		uploadStatus, renameStatus, name)

	dangling := 0
	apps, err := e.st.ListApps()
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	for _, a := range apps {
		for _, v := range e.versionsOfID(a.ID) {
			p := filepath.Join(e.dataDir, a.Name, v.Version, v.Filename)
			if _, err := os.Stat(p); err != nil {
				dangling++
				t.Logf("observation: row %s/%s has no file at %s (%v)", a.Name, v.Version, p, err)
			}
		}
	}
	t.Logf("observation: dangling rows after the rename/upload race: %d; orphan dirs: %v",
		dangling, e.orphanDirs())

	// Требование только одно: сервис не сломался.
	if status, _ := e.appJSONOf(name); status != http.StatusOK {
		t.Errorf("app unreachable after the rename/upload race: status = %d", status)
	}
	resp := e.api("GET", "/api/apps", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/apps after the race: status = %d, want 200", resp.StatusCode)
	}
}

// waitForTempUpload blocks until files.Save has created its temp file under
// {Root}/.tmp, i.e. the upload handler is provably inside Save and streaming
// the body. Возвращает false, если не дождались.
func (e *env) waitForTempUpload(timeout time.Duration) bool {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ents, err := os.ReadDir(filepath.Join(e.dataDir, ".tmp"))
		if err == nil {
			for _, ent := range ents {
				if strings.HasPrefix(ent.Name(), "upload-") {
					return true
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestRenameWhileUploadIsStreamingObserved пришпиливает то самое чередование,
// которое авторы волны отметили как известную шероховатость: переименование
// происходит, пока загрузка ещё читает тело. Тест НИЧЕГО не требует от исхода —
// он синхронизируется на временном файле files.Save (а не на sleep), чтобы
// чередование было воспроизводимым, и протоколирует получившееся состояние
// хранилища. Требование одно: сервис остаётся работоспособным.
func TestRenameWhileUploadIsStreamingObserved(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("moving")
	e.seed("moving", "1.0.0") // каталог приложения уже есть, значит его реально двигают

	pr, pw := io.Pipe()
	defer pw.Close() // иначе раннее падение теста оставит запрос в полёте и подвесит srv.Close
	req, err := http.NewRequest("PUT", e.srv.URL+"/api/apps/moving/versions/2.0.0?filename=late.bin&platform="+testPlatform, pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth(testUser, testPass)

	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			done <- result{0, err}
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		done <- result{resp.StatusCode, nil}
	}()

	// Первая половина тела: после неё хендлер гарантированно внутри Save.
	if _, err := pw.Write(bytes.Repeat([]byte("A"), 4096)); err != nil {
		t.Fatalf("write first half: %v", err)
	}
	if !e.waitForTempUpload(5 * time.Second) {
		pw.Close()
		<-done
		t.Skip("upload did not reach files.Save in time; interleaving not reproducible here")
	}

	// Переименовываем ровно в этот момент.
	resp := e.renameViaAPI("moving", `{"name":"moved"}`)
	renameStatus := resp.StatusCode
	resp.Body.Close()

	pw.Write(bytes.Repeat([]byte("B"), 4096))
	pw.Close()
	res := <-done

	t.Logf("observed: rename status = %d, upload status = %d, upload transport err = %v",
		renameStatus, res.status, res.err)

	// Протоколируем итоговое состояние: где строка и где файл.
	apps, err := e.st.ListApps()
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	dangling := 0
	for _, a := range apps {
		for _, v := range e.versionsOfID(a.ID) {
			p := filepath.Join(e.dataDir, a.Name, v.Version, v.Filename)
			if _, err := os.Stat(p); err != nil {
				dangling++
				t.Logf("observation: row %s/%s points at %s, which is not there", a.Name, v.Version, p)
			}
		}
	}
	t.Logf("observation: dangling rows = %d, orphan dirs = %v, data dir = %v",
		dangling, e.orphanDirs(), e.topLevelDirs())
	if dangling > 0 {
		t.Logf("observation: /download of such a version answers 500 " +
			"(row present, file elsewhere) — known roughness per the T12–T14 reports")
	}

	// Единственное требование: сервис жив.
	name := "moving"
	if renameStatus == http.StatusOK {
		name = "moved"
	}
	if status, _ := e.appJSONOf(name); status != http.StatusOK {
		t.Errorf("app unreachable after the interleaving: status = %d", status)
	}
	list := e.api("GET", "/api/apps", nil, nil)
	list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Errorf("GET /api/apps after the interleaving: status = %d, want 200", list.StatusCode)
	}
}

// TestStorageInvariantAfterFullWave5Scenario прогоняет длинную детерминированную
// цепочку из всех операций волны 5 (через API и UI вперемешку) и в конце
// проверяет главный инвариант: в БД нет строк, указывающих на несуществующие
// файлы, а на диске нет чужих каталогов.
func TestStorageInvariantAfterFullWave5Scenario(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")

	for _, name := range []string{"one", "two", "three", "four"} {
		e.createApp(name)
	}
	for _, v := range []string{"1.0.0", "1.2.0", "2.0.0"} {
		e.seed("one", v)
		e.seed("two", v)
	}
	e.seed("three", "0.1.0")
	// "four" остаётся без версий.

	// 1. Переименование через API, затем через UI, затем обратно.
	resp := e.renameViaAPI("one", `{"name":"one-renamed"}`)
	resp.Body.Close()
	e.uiPageBody(c, "/apps/one-renamed", http.StatusOK)
	resp = e.renameViaUI(c, "one-renamed", "one", "back to the start")
	resp.Body.Close()

	// 2. Пин, потом удаление запиненной версии.
	resp = e.api("POST", "/api/apps/two/latest", strings.NewReader(`{"version":"1.2.0"}`), jsonHdr)
	resp.Body.Close()
	resp = e.deleteVersionAPI("two", "1.2.0")
	resp.Body.Close()

	// 3. Удаление версии через UI.
	e.uiPageBody(c, "/apps/one", http.StatusOK)
	resp = e.deleteVersionUI(c, "one", "1.0.0")
	resp.Body.Close()

	// 4. Удаление последней версии приложения.
	resp = e.deleteVersionAPI("three", "0.1.0")
	resp.Body.Close()

	// 5. Переименование приложения без версий и удаление приложения целиком.
	resp = e.renameViaAPI("four", `{"name":"four-renamed"}`)
	resp.Body.Close()
	resp = e.deleteAppAPI("two")
	resp.Body.Close()

	// 6. Повторная загрузка в приложение, из которого всё удалили.
	e.seed("three", "9.9.9")

	// --- инвариант ---
	e.assertNoDanglingRows()

	if orphans := e.orphanDirs(); len(orphans) != 0 {
		t.Errorf("orphan directories on disk with no app row: %v", orphans)
	}
	// Приложения без версий не должны оставлять за собой пустых каталогов
	// после того, как все их версии удалены.
	for _, name := range []string{"one", "three", "four-renamed"} {
		if status, _ := e.appJSONOf(name); status != http.StatusOK {
			t.Errorf("app %q lost during the scenario: status = %d", name, status)
		}
	}
	if status, _ := e.appJSONOf("two"); status != http.StatusNotFound {
		t.Errorf("deleted app %q is still reachable", "two")
	}
	mustNotExist(t, e.appDir("two"), "deleted app dir at the end of the scenario")
	mustNotExist(t, e.appDir("one-renamed"), "intermediate rename target")

	if got := strings.Join(e.versionNamesOf("one"), ","); got != "1.2.0,2.0.0" {
		t.Errorf("versions of one = %q, want 1.2.0,2.0.0", got)
	}
	if got := e.latestOf("one"); got != "2.0.0" {
		t.Errorf("latest of one = %q, want 2.0.0", got)
	}
}

// TestDeleteAppNamedLikeTheDatabaseFile: имя приложения — это имя каталога
// внутри data-dir, где по умолчанию лежит и сама БД (`{data-dir}/apprepo.db`).
// Удаление приложения делает os.RemoveAll по этому пути, поэтому приложение с
// таким именем не должно уметь снести файл БД.
func TestDeleteAppNamedLikeTheDatabaseFile(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	dbPath := e.cfg.DBPath
	if filepath.Dir(dbPath) != e.dataDir {
		t.Skipf("test assumes the default layout (DB inside the data dir), got %s", dbPath)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database file missing before the test: %v", err)
	}

	// Имена «apprepo.db» и «apprepo.db-wal» проходят naming.ValidateAppName:
	// регулярка разрешает точку и дефис в середине.
	for _, victim := range []string{"apprepo.db", "apprepo.db-wal"} {
		t.Run(victim, func(t *testing.T) {
			target := filepath.Join(e.dataDir, victim)
			body, err := jsonBody(map[string]string{"name": victim, "description": "collides"})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			resp := e.api("POST", "/api/apps", strings.NewReader(body), jsonHdr)
			created := resp.StatusCode
			resp.Body.Close()
			if created != http.StatusCreated {
				t.Skipf("app named %q was refused at creation (status %d) — collision not reachable",
					victim, created)
			}
			existedBefore := false
			if _, err := os.Stat(target); err == nil {
				existedBefore = true
			}

			resp = e.deleteAppAPI(victim)
			status := resp.StatusCode
			resp.Body.Close()
			t.Logf("DELETE /api/apps/%s: status = %d (SQLite file existed before: %v)",
				victim, status, existedBefore)

			if !existedBefore {
				t.Skipf("%s does not exist in this run, nothing to destroy", target)
			}
			if _, err := os.Stat(target); err != nil {
				t.Errorf("deleting the app named %q removed the live SQLite file %s: %v"+
					"\n  the data dir doubles as the file-storage root, so files.RemoveApp"+
					"\n  os.RemoveAll's whatever happens to share a name with the app",
					victim, target, err)
			}
		})
	}
	_ = dbPath
}

// TestUIEditAndDeleteOnMissingAppAre404: новые UI-POST на несуществующее или
// невалидное имя приложения отвечают 404 и ничего не трогают.
func TestUIEditAndDeleteOnMissingAppAre404(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("present")
	content := e.seed("present", "1.0.0")
	e.uiPageBody(c, "/apps/present", http.StatusOK)
	tok := e.csrfOf(c)

	for _, tc := range []struct {
		name string
		path string
		form url.Values
	}{
		{"edit_missing_app", "/apps/nosuchapp/edit",
			url.Values{"csrf_token": {tok}, "name": {"whatever"}}},
		{"edit_reserved_name_in_path", "/apps/latest/edit",
			url.Values{"csrf_token": {tok}, "name": {"whatever"}}},
		{"delete_missing_app", "/apps/nosuchapp/delete",
			url.Values{"csrf_token": {tok}, "confirm": {"nosuchapp"}}},
		{"delete_version_of_missing_app", "/apps/nosuchapp/versions/1.0.0/delete",
			url.Values{"csrf_token": {tok}}},
		{"delete_missing_version", "/apps/present/versions/9.9.9/delete",
			url.Values{"csrf_token": {tok}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.uiPost(c, tc.path, tc.form)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("POST %s: status = %d, want 404", tc.path, resp.StatusCode)
			}
		})
	}

	if got := e.mustDownload("present", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("the existing app was disturbed by 404-ing requests")
	}
	e.assertNoDanglingRows()
}

// TestRenameOntoAnExistingDirectoryIs409 документирует асимметрию волны 5:
// files.RenameApp отказывается переезжать на уже существующий путь внутри
// data-dir (Lstat → ErrFileExists → 409, строка в БД откатывается), тогда как
// files.RemoveApp такой проверки не делает (см.
// TestDeleteAppNamedLikeTheDatabaseFile).
func TestRenameOntoAnExistingDirectoryIs409(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	if filepath.Dir(e.cfg.DBPath) != e.dataDir {
		t.Skip("test assumes the default layout (DB inside the data dir)")
	}
	e.createApp("mover")
	content := e.seed("mover", "1.0.0")

	body, err := jsonBody(map[string]string{"name": "apprepo.db"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantJSONError(t, e.renameViaAPI("mover", body), http.StatusConflict, "already_exists")

	// Строка откатилась: приложение по-прежнему под старым именем и качается.
	if status, _ := e.appJSONOf("mover"); status != http.StatusOK {
		t.Errorf("the DB row was not rolled back after the refused disk rename")
	}
	if status, _ := e.appJSONOf("apprepo.db"); status != http.StatusNotFound {
		t.Errorf("the app is reachable under the refused new name")
	}
	if got := e.mustDownload("mover", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("bytes changed after the refused rename")
	}
	mustExist(t, e.cfg.DBPath, "database file after a refused rename onto it")
	e.assertNoDanglingRows()
}
