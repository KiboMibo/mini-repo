package integration

// Окно «тело ушло — ответ не пришёл» (R7-sec, S1). Кнопка «Cancel upload» и
// обрыв сети после того, как тело целиком доехало до сервера, публикацию уже
// не отменяют: хендлер дочитывает, публикует файл и создаёт строку, а об
// оборванном соединении узнаёт только на записи ответа. Здесь фиксируется
// правдивое поведение сервера — и то, что скрипт больше не обещает обратного.
// Задача F18.

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apprepo/internal/store"
)

// waitVersion polls for the version row to appear. Клиент ушёл, ответа никто
// не читает, поэтому момента «сервер закончил» снаружи не видно — опрос с
// дедлайном вместо фиксированной паузы, как и в тестах на обрыв (R7-test).
func (e *env) waitVersion(appName, version string, d time.Duration) *store.Version {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for {
		a, err := e.st.GetApp(appName)
		if err != nil {
			e.t.Fatalf("GetApp(%q): %v", appName, err)
		}
		if a != nil {
			v, err := e.st.GetVersion(a.ID, version)
			if err != nil {
				e.t.Fatalf("GetVersion(%q, %q): %v", appName, version, err)
			}
			if v != nil {
				return v
			}
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cookieHeader renders the UI client's cookies for a hand-written request.
func (e *env) cookieHeader(c *http.Client) string {
	e.t.Helper()
	u, _ := url.Parse(e.srv.URL)
	parts := []string{}
	for _, ck := range c.Jar.Cookies(u) {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

// TestUploadSurvivesClientLeavingAfterFullBody: клиент отправляет тело
// целиком и уходит, не читая ответа (RST — ровно то, что делает браузер на
// xhr.abort()). Версия обязана оказаться в БД и на диске: сервер к этому
// моменту работу уже сделал, и «отмены» здесь нет. Ради этого факта и
// переписаны тексты в шаблоне — обещать «ничего не сохранено» нельзя.
func TestUploadSurvivesClientLeavingAfterFullBody(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	if e.csrfOf(c) == "" {
		t.Fatal("нет CSRF-куки после входа")
	}

	content := bytes.Repeat([]byte("late-release-payload\n"), 4096)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	// Порядок частей — как в форме: file последним.
	for _, f := range [][2]string{{"csrf_token", e.csrfOf(c)}, {"version", "8.0.0"}, {"sha256", ""}, {"platform_os", testPlatform}} {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			t.Fatalf("WriteField %s: %v", f[0], err)
		}
	}
	fw, err := mw.CreateFormFile("file", "late.bin")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	fw.Write(content)
	mw.Close()

	conn := e.dialServer()
	req := "POST /apps/myapp/versions HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(e.srv.URL, "http://") + "\r\n" +
		"Cookie: " + e.cookieHeader(c) + "\r\n" +
		"Content-Type: " + mw.FormDataContentType() + "\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", body.Len())
	if _, err := io.WriteString(conn, req+body.String()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Дать серверу дочитать тело, затем оборвать соединение по-жёсткому:
	// SetLinger(0) + Close даёт RST, как браузер на xhr.abort(). Пауза — не
	// про ширину окна (она зависит от машины и от прокси перед сервисом), а
	// про то, чтобы в сокете не осталось неотправленного: RST его выбросил бы,
	// и получился бы уже проверенный в R7-test обрыв на середине тела.
	time.Sleep(200 * time.Millisecond)
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.SetLinger(0); err != nil {
			t.Fatalf("SetLinger: %v", err)
		}
	}
	conn.Close()

	v := e.waitVersion("myapp", "8.0.0", 5*time.Second)
	if v == nil {
		t.Fatal("версии 8.0.0 нет в БД: тело доехало целиком, публикацию обрыв ответа не отменяет — " +
			"если поведение изменилось, тексты в app.html надо приводить в соответствие")
	}
	if v.Filename != "late.bin" || v.SizeBytes != int64(len(content)) {
		t.Errorf("строка версии = {%q, %d}, want {\"late.bin\", %d}", v.Filename, v.SizeBytes, len(content))
	}
	path := filepath.Join(e.versionDir("myapp", "8.0.0"), "late.bin")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("файла опубликованной версии нет на диске: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("содержимое файла на диске отличается от отправленного (%d против %d байт)", len(got), len(content))
	}
	e.wantNoTmpLeftovers("публикация после ухода клиента")
}

// TestUploadScriptDoesNotPromiseRollback: скрипт на странице не обещает того,
// чего не знает. Проверяется по коду в отданной странице — браузерного раннера
// в проекте нет (см. R7-test, «Что из T22 осталось непроверяемым»).
func TestUploadScriptDoesNotPromiseRollback(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	page := e.appPage(c, "myapp")

	// Кнопка отмены исчезает, как только тело ушло: отменять уже нечего.
	upl := strings.Index(page, "xhr.upload.onload")
	if upl < 0 {
		t.Fatal("на странице нет обработчика xhr.upload.onload")
	}
	end := strings.Index(page[upl:], "xhr.onload")
	if end < 0 {
		t.Fatal("не нашёл конец xhr.upload.onload")
	}
	if h := page[upl : upl+end]; !strings.Contains(h, "abort.hidden = true") {
		t.Errorf("xhr.upload.onload не прячет кнопку отмены:\n%s", h)
	}

	// Утверждения «ничего не сохранено» в ветках обрыва не осталось.
	for _, bad := range []string{"Nothing was stored", "nothing was stored"} {
		if strings.Contains(page, bad) {
			t.Errorf("страница всё ещё утверждает %q — после ухода тела это неправда", bad)
		}
	}
	// Флаг «тело ушло» и текст для этого случая на месте.
	for _, want := range []string{"sent = true", "may have published this version"} {
		if !strings.Contains(page, want) {
			t.Errorf("в скрипте нет %q — ветка «обрыв после полного тела» потеряна", want)
		}
	}
	// Адрес из ответа проверяется на свой origin, а страница входа не
	// считается успехом (R7-sec, S2).
	for _, want := range []string{"u.origin === location.origin", "'/login?m=session-expired&next='"} {
		if !strings.Contains(page, want) {
			t.Errorf("в скрипте нет %q — переход по ответу сервера снова без проверки", want)
		}
	}
}
