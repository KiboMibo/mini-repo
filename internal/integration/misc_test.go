package integration

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestConcurrentPutSameVersionRollsBack: два одновременных PUT одной версии —
// второй завершившийся получает 409 от UNIQUE в БД (поздняя ветка, после
// ранней проверки), его файл откатывается, файл победителя цел.
func TestConcurrentPutSameVersionRollsBack(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("race")

	pr, pw := io.Pipe()
	// Тело «медленного» запроса обязано закрыться даже если тест упадёт раньше
	// строки pw.Close(): иначе запрос остаётся в полёте, и httptest.Server.Close
	// в t.Cleanup виснет вместе со всем пакетом (F20).
	defer pw.Close()
	slowDone := make(chan *http.Response, 1)
	go func() {
		req, err := http.NewRequest("PUT", e.srv.URL+"/api/apps/race/versions/1.0.0?filename=slow-bin&platform="+testPlatform, pr)
		if err != nil {
			panic(err)
		}
		req.SetBasicAuth(testUser, testPass)
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			panic(err)
		}
		slowDone <- resp
	}()

	// Write блокируется, пока хендлер не начал читать тело, — значит, ранняя
	// проверка дубля уже пройдена и «медленный» запрос завис в files.Save.
	if _, err := pw.Write([]byte("s")); err != nil {
		t.Fatalf("pipe write: %v", err)
	}

	// «Быстрый» запрос успевает создать версию целиком.
	fast := []byte("fast-content")
	e.mustPutVersion("race", "1.0.0", "?filename=fast-bin", fast, "")

	// Дописываем и закрываем тело медленного — он доходит до CreateVersion
	// и обязан получить 409 с откатом своего файла.
	pw.Write([]byte("low-content"))
	pw.Close()

	var resp *http.Response
	select {
	case resp = <-slowDone:
	case <-time.After(10 * time.Second):
		t.Fatal("медленный PUT не завершился")
	}
	wantJSONError(t, resp, http.StatusConflict, "already_exists")

	if _, err := os.Stat(filepath.Join(e.dataDir, "race", "1.0.0", "slow-bin")); !os.IsNotExist(err) {
		t.Errorf("файл проигравшего должен быть откатан, stat err = %v", err)
	}
	dl := e.api("GET", "/download/race/1.0.0", nil, nil)
	defer dl.Body.Close()
	if got := readBody(t, dl); got != string(fast) {
		t.Errorf("содержимое версии = %q, want %q (победитель)", got, fast)
	}
}

// TestSetLatestAutoOnEmptyAppReturnsNull: auto без версий — 200 и JSON null.
func TestSetLatestAutoOnEmptyAppReturnsNull(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("void")
	resp := e.api("POST", "/api/apps/void/latest", strings.NewReader(`{"version":"auto"}`), jsonHdr)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := strings.TrimSpace(readBody(t, resp)); body != "null" {
		t.Errorf("body = %q, want null", body)
	}
}

// TestBackslashFilenameStoredAsBasename: Windows-браузеры шлют полный путь
// с обратными слешами — сохраняться должен только basename.
func TestBackslashFilenameStoredAsBasename(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("winup")
	resp := e.uploadRawFilename(c, "winup", "1.0.0", `C:\Users\bob\evil-bs`, []byte("x"), e.csrfOf(c))
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "winup", "1.0.0", "evil-bs")); err != nil {
		t.Errorf("файл должен лежать под basename evil-bs: %v", err)
	}
}

// TestMultipartWithoutFileAndBadCSRF: и файла нет, и токен чужой — 403.
func TestMultipartWithoutFileAndBadCSRF(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("nf")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("csrf_token", "stolen")
	mw.WriteField("version", "1.0.0")
	mw.Close()
	req, _ := http.NewRequest("POST", e.srv.URL+"/apps/nf/versions", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestClosedStoreDegradesTo500: при недоступной БД middleware отвечают 500,
// а не паникуют и не пропускают без аутентификации.
func TestClosedStoreDegradesTo500(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("basic_auth_route", func(t *testing.T) {
		resp := e.api("GET", "/api/apps", nil, nil)
		wantJSONError(t, resp, http.StatusInternalServerError, "internal")
	})

	t.Run("session_route", func(t *testing.T) {
		resp, err := c.Get(e.srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", resp.StatusCode)
		}
	})
}

// TestGetUserByIDMissing: (nil, nil) для несуществующего id — контракт
// хелпера T4 (внутренняя граница session-middleware).
func TestGetUserByIDMissing(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	u, err := e.st.GetUserByID(99999)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u != nil {
		t.Errorf("GetUserByID(99999) = %+v, want nil", u)
	}
}

// TestConcurrentPutSameFileGets409: гонка двух PUT одной версии с одним именем
// файла — проигравший получает 409 (атомарный os.Link в files.Save), файл и
// строка БД победителя нетронуты, путь ФС наружу не уходит.
func TestConcurrentPutSameFileGets409(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("race2")

	pr, pw := io.Pipe()
	defer pw.Close() // см. TestConcurrentPutSameVersionRollsBack: иначе висит весь пакет
	slowDone := make(chan *http.Response, 1)
	go func() {
		req, err := http.NewRequest("PUT", e.srv.URL+"/api/apps/race2/versions/1.0.0?filename=bin&platform="+testPlatform, pr)
		if err != nil {
			panic(err)
		}
		req.SetBasicAuth(testUser, testPass)
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			panic(err)
		}
		slowDone <- resp
	}()

	// Write блокируется, пока хендлер не начал читать тело, — ранняя проверка
	// дубля пройдена, «медленный» завис в files.Save до публикации.
	if _, err := pw.Write([]byte("s")); err != nil {
		t.Fatalf("pipe write: %v", err)
	}

	// «Быстрый» PUT той же версии и того же имени файла успевает целиком.
	fast := []byte("fast-content")
	e.mustPutVersion("race2", "1.0.0", "?filename=bin", fast, "")

	pw.Write([]byte("low-content"))
	pw.Close()

	var resp *http.Response
	select {
	case resp = <-slowDone:
	case <-time.After(10 * time.Second):
		t.Fatal("медленный PUT не завершился")
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "already_exists") {
		t.Errorf("body = %s, want already_exists", body)
	}
	if strings.Contains(string(body), e.dataDir) {
		t.Errorf("ответ раскрывает путь ФС: %s", body)
	}
	// Файл победителя цел и скачивается байт-в-байт.
	if b, err := os.ReadFile(filepath.Join(e.dataDir, "race2", "1.0.0", "bin")); err != nil || string(b) != string(fast) {
		t.Errorf("файл победителя повреждён: %q, %v", b, err)
	}
	dl := e.api("GET", "/download/race2/1.0.0", nil, nil)
	defer dl.Body.Close()
	if got := readBody(t, dl); got != string(fast) {
		t.Errorf("скачанное = %q, want %q", got, fast)
	}
}

// TestDataDirAndDBPermissions: каталог данных 0700, файлы БД 0600 — токены
// сессий и хеши паролей не читаются другими локальными пользователями.
func TestDataDirAndDBPermissions(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	fi, err := os.Stat(e.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("data dir mode = %o, want 700", got)
	}
	for _, suf := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(e.cfg.DBPath + suf)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s: mode = %o, want 600", e.cfg.DBPath+suf, got)
		}
	}
}
