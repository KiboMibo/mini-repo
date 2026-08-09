package integration

// Гонка «переименование во время загрузки» (находка В1 приёмки волны 5,
// задача F10). Тело загрузки льётся медленно; в середине приложение
// переименовывают. Исход обязан быть консистентным: либо файл лежит там, куда
// указывает строка в БД, либо загрузка отказана и на диске не осталось ни
// временного файла, ни осиротевшего каталога со старым именем. 500 на
// последующем /download не допускается ни при каком чередовании.

import (
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pausedBody streams head, then blocks until release is closed, then streams
// tail. Такое тело детерминированно «висит» на сервере внутри files.Prepare,
// пока тест выполняет параллельный запрос.
type pausedBody struct {
	head, tail []byte
	release    <-chan struct{}
	off        int
	paused     bool
}

func (b *pausedBody) Read(p []byte) (int, error) {
	if b.off < len(b.head) {
		n := copy(p, b.head[b.off:])
		b.off += n
		return n, nil
	}
	if !b.paused {
		b.paused = true
		<-b.release
	}
	i := b.off - len(b.head)
	if i >= len(b.tail) {
		return 0, io.EOF
	}
	n := copy(p, b.tail[i:])
	b.off += n
	return n, nil
}

// waitForTempBytes waits until the storage scratch dir holds a temp upload of
// at least want bytes. Это точка синхронизации теста: временный файл создаётся
// уже после разбора имени приложения и проверки дубля, значит хендлер
// гарантированно дошёл до стриминга тела и ещё не опубликовал файл.
func (e *env) waitForTempBytes(want int64) {
	e.t.Helper()
	tmpDir := filepath.Join(e.dataDir, ".tmp")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(tmpDir)
		for _, ent := range ents {
			if fi, err := ent.Info(); err == nil && fi.Size() >= want {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	e.t.Fatalf("upload of %d bytes never reached %s", want, tmpDir)
}

// wantNoTempLeftovers asserts the scratch dir holds no abandoned upload.
func (e *env) wantNoTempLeftovers() {
	e.t.Helper()
	ents, err := os.ReadDir(filepath.Join(e.dataDir, ".tmp"))
	if err != nil {
		if !os.IsNotExist(err) {
			e.t.Fatalf("ReadDir .tmp: %v", err)
		}
		return
	}
	for _, ent := range ents {
		e.t.Errorf("temp file %q left behind in .tmp after the upload failed", ent.Name())
	}
}

// renameApp renames an app over the API and asserts 200.
func (e *env) renameApp(from, to string) {
	e.t.Helper()
	body, err := jsonBody(map[string]string{"name": to})
	if err != nil {
		e.t.Fatalf("jsonBody: %v", err)
	}
	resp := e.api("PATCH", "/api/apps/"+from, strings.NewReader(body), jsonHdr)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("PATCH /api/apps/%s -> %s: status = %d, want 200; body: %s",
			from, to, resp.StatusCode, readBody(e.t, resp))
	}
}

// wantConsistentAfterRace asserts the invariant both branches of the race must
// satisfy: the renamed app serves what it owns, the old name is gone from disk
// and from the API, nothing is left in .tmp, and renaming back is not blocked
// by a stray directory (до F10 именно это требовало ручной чистки).
func (e *env) wantConsistentAfterRace(old, renamed string, seeded []byte) {
	e.t.Helper()
	mustNotExist(e.t, e.appDir(old), "app directory of the old name after rename")
	e.wantNoTempLeftovers()
	if got := e.mustDownload(renamed, "1.0.0"); string(got) != string(seeded) {
		e.t.Errorf("download %s/1.0.0 returned %d bytes, want the seeded %d", renamed, len(got), len(seeded))
	}
	// Каждая строка в БД обязана указывать на существующий файл: любой 500
	// здесь — тот самый рассинхрон, ради которого заведена задача.
	for _, v := range e.versionNamesOf(renamed) {
		e.wantDownloadStatus(renamed, v, http.StatusOK)
	}
	if dirs := e.topLevelDirs(); len(dirs) != 1 || dirs[0] != renamed {
		e.t.Errorf("data dir holds %v, want only %q", dirs, renamed)
	}
	e.renameApp(renamed, old) // осиротевший каталог отказал бы это 409
}

// TestUploadDuringRenameAPI: PUT с медленным телом и PATCH-переименование
// посередине. До F10 PUT отвечал 201, файл ложился под СТАРЫМ именем каталога,
// строка в БД принадлежала уже новому — /download отдавал 500, а лишний
// каталог блокировал переименование обратно.
func TestUploadDuringRenameAPI(t *testing.T) {
	e := newEnv(t, 1<<20)
	e.createApp("old")
	seeded := e.seed("old", "1.0.0")

	release := make(chan struct{})
	// Пауза обязана сняться даже если тест упадёт раньше своего close: иначе
	// тело остаётся недописанным, запрос — в полёте, и httptest.Server.Close в
	// t.Cleanup виснет вместе со всем пакетом (F20).
	unpause := sync.OnceFunc(func() { close(release) })
	defer unpause()
	body := &pausedBody{
		head:    []byte(strings.Repeat("a", 4096)),
		tail:    []byte("tail"),
		release: release,
	}
	done := make(chan *http.Response, 1)
	go func() {
		done <- e.api("PUT", "/api/apps/old/versions/2.0.0?filename=old-2.0.0&platform="+testPlatform, body, nil)
	}()

	e.waitForTempBytes(int64(len(body.head)))
	e.renameApp("old", "renamed")
	unpause()

	resp := <-done
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("PUT during rename: status = %d, want 409; body: %s",
			resp.StatusCode, readBody(t, resp))
	}
	// Версия не создана — 404, а не 500 «файл потерялся».
	e.wantDownloadStatus("renamed", "2.0.0", http.StatusNotFound)
	mustNotExist(t, e.versionDir("renamed", "2.0.0"), "version dir of the refused upload")
	e.wantConsistentAfterRace("old", "renamed", seeded)
}

// TestUploadDuringRenameUI: то же чередование через форму UI (multipart),
// хендлер другой (internal/web) — рубеж обязан быть общим.
func TestUploadDuringRenameUI(t *testing.T) {
	e := newEnv(t, 1<<20)
	e.createApp("old")
	seeded := e.seed("old", "1.0.0")

	c := e.uiClient()
	e.login(c, "/")
	e.uiGet(c, "/apps/old").Body.Close() // выдаёт CSRF-куку
	tok := e.csrfOf(c)
	if tok == "" {
		t.Fatal("no CSRF cookie")
	}

	head := []byte(strings.Repeat("a", 4096))
	release := make(chan struct{})
	unpause := sync.OnceFunc(func() { close(release) }) // см. выше: иначе виснет весь пакет
	defer unpause()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		// file — последняя часть формы (контракт хендлера).
		for _, kv := range [][2]string{{"csrf_token", tok}, {"version", "2.0.0"}, {"sha256", ""}, {"platform_os", testPlatform}} {
			mw.WriteField(kv[0], kv[1])
		}
		fw, err := mw.CreateFormFile("file", "old-2.0.0")
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		fw.Write(head)
		<-release
		fw.Write([]byte("tail"))
		mw.Close()
		pw.Close()
	}()

	done := make(chan *http.Response, 1)
	go func() {
		req, err := http.NewRequest("POST", e.srv.URL+"/apps/old/versions", pr)
		if err != nil {
			t.Errorf("NewRequest: %v", err)
			done <- nil
			return
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := c.Do(req)
		if err != nil {
			t.Errorf("POST upload: %v", err)
		}
		done <- resp
	}()

	e.waitForTempBytes(int64(len(head)))
	e.renameApp("old", "renamed")
	unpause()

	resp := <-done
	if resp == nil {
		t.Fatal("upload request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("UI upload during rename: status = %d, want 409", resp.StatusCode)
	}
	if b := readBody(t, resp); !strings.Contains(b, "renamed or removed") {
		t.Errorf("error page does not explain the conflict; body: %s", b)
	}
	e.wantDownloadStatus("renamed", "2.0.0", http.StatusNotFound)
	e.wantConsistentAfterRace("old", "renamed", seeded)
}

// TestUploadsRacingRenameStayConsistent прогоняет то же чередование без
// синхронизации: несколько загрузок и переименование стартуют одновременно.
// Проверяется инвариант, а не конкретные коды: что бы ни выиграло, каждая
// строка в БД указывает на существующий файл. Полезен под -race.
func TestUploadsRacingRenameStayConsistent(t *testing.T) {
	e := newEnv(t, 1<<20)
	e.createApp("old")
	e.seed("old", "0.1.0")

	versions := []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, v := range versions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			content := payloadFor("old", v)
			resp := e.putVersion("old", v, "", content, sha256hex(content))
			resp.Body.Close()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		e.renameApp("old", "renamed")
	}()
	close(start)
	wg.Wait()

	for _, v := range e.versionNamesOf("renamed") {
		e.wantDownloadStatus("renamed", v, http.StatusOK)
	}
	if dirs := e.topLevelDirs(); len(dirs) != 1 || dirs[0] != "renamed" {
		t.Errorf("data dir holds %v, want only \"renamed\"", dirs)
	}
	e.wantNoTempLeftovers()
}
