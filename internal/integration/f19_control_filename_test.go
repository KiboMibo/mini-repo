package integration

// F19 (R7-qa, находка 1): управляющий символ в имени файла — клиентская ошибка,
// а не сбой сервиса. До правки NUL проходил naming.ValidateFilename, тело
// выкачивалось целиком, и падал уже os.Link («invalid argument») — 500 на
// пользовательском вводе, в мониторинге неотличимый от настоящей поломки.
//
// Здесь проверяется три вещи, которых на уровне naming не видно:
//   - оба интерфейса отвечают 4xx и ничего не оставляют на диске и в БД;
//   - отказ приходит ДО чтения тела (иначе смысл фикса теряется наполовину:
//     на двухгигабайтном архиве это 2 ГБ трафика ради 400);
//   - обычная заливка на ту же версию после отказа по-прежнему даёт 201.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// controlFilenames — имена, которых файловая система и заголовки не переживают.
// NUL первый: именно он ломал os.Link и породил находку.
var controlFilenames = map[string]string{
	"NUL":     "a\x00b.tar.gz",
	"newline": "a\nb.tar.gz",
	"CR":      "a\rb.tar.gz",
	"DEL":     "a\x7fb.tar.gz",
	"C1":      "ab.tar.gz",
}

// TestPutVersionControlCharFilenameIsClientError: API отвечает 400
// invalid_filename, а не 500, и не оставляет следов.
func TestPutVersionControlCharFilenameIsClientError(t *testing.T) {
	for name, filename := range controlFilenames {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, defaultMaxUpload)
			e.createApp("myapp")
			payload := tarGzBytes(t, multiFileRelease())

			resp := e.putVersionRaw("myapp", "1.0.0", "?filename="+url.QueryEscape(filename), payload, "")
			wantJSONError(t, resp, http.StatusBadRequest, "invalid_filename")
			e.wantNoVersion("myapp", "1.0.0", "управляющий символ в ?filename=")
			e.wantNoTmpLeftovers("после отказа по управляющему символу")

			// Граница из отчёта приёмки: система восстанавливается сама —
			// та же версия с нормальным именем заливается следом.
			obj := e.mustPutVersion("myapp", "1.0.0", "?filename=myapp-1.0.0.tar.gz", payload, sha256hex(payload))
			if obj["filename"] != "myapp-1.0.0.tar.gz" {
				t.Errorf("после отказа перезаливка дала filename = %v", obj["filename"])
			}
			e.assertNoDanglingRows()
		})
	}
}

// TestUIUploadControlCharFilenameIsRefused: тот же ввод по пути UI-формы.
// naming.ValidateFilename — единственная точка проверки имени, поэтому правка
// закрывает оба интерфейса; тест держит это свойство, а не повторяет unit-тест.
func TestUIUploadControlCharFilenameIsRefused(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("myapp")
	e.uiPageBody(c, "/apps/myapp", http.StatusOK)

	resp := e.uploadRawFilename(c, "myapp", "1.0.0", "a\x00b.tar.gz", []byte("payload"), e.csrfOf(c))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("UI: status = %d, want 400", resp.StatusCode)
	}
	e.wantNoVersion("myapp", "1.0.0", "управляющий символ в имени файла формы")
	e.wantNoTmpLeftovers("после отказа UI-формы")
}

// TestControlCharFilenameRefusedBeforeBody меряет, сколько байт тела успел
// прочитать сервер до отказа: ноль. Мера прямая — клиент объявляет
// Content-Length на 512 МиБ и не отправляет НИ ОДНОГО байта тела; полный ответ
// 400 при этом всё равно приходит, то есть хендлер до чтения тела не дошёл.
//
// Тест умеет падать: контрольная половина шлёт тот же запрос с годным именем и
// так же не шлёт тела — там ответа нет, сервер ждёт байты. Если проверка имени
// уедет за files.Prepare (как было до F19), первая половина повторит поведение
// второй и упадёт по таймауту, а не молча позеленеет.
func TestControlCharFilenameRefusedBeforeBody(t *testing.T) {
	const declared = 512 << 20 // объявленное тело, которого сервер не получит

	// headersOnly отправляет запрос без единого байта тела и возвращает первую
	// строку ответа, либо "" если сервер за отведённое время не ответил.
	headersOnly := func(e *env, version, filename string, wait time.Duration) (string, string) {
		e.t.Helper()
		conn := e.dialServer()
		req := fmt.Sprintf("PUT /api/apps/myapp/versions/%s?filename=%s HTTP/1.1\r\n", version, url.QueryEscape(filename)) +
			"Host: " + strings.TrimPrefix(e.srv.URL, "http://") + "\r\n" +
			"Authorization: " + basicAuthHeader() + "\r\n" +
			fmt.Sprintf("Content-Length: %d\r\n", declared) +
			"Content-Type: application/octet-stream\r\n\r\n"
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("write headers: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return "", ""
		}
		var body bytes.Buffer
		io.Copy(&body, br) // сервер закрывает соединение после отказа — читаем до конца
		conn.Close()
		return strings.TrimSpace(status), body.String()
	}

	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	status, body := headersOnly(e, "1.0.0", "a\x00b.tar.gz", 5*time.Second)
	if !strings.Contains(status, "400") {
		t.Fatalf("отказ не пришёл до тела: status line = %q (сервер ждал байты, которых не было)", status)
	}
	if !strings.Contains(body, `"invalid_filename"`) {
		t.Errorf("тело ответа = %q, want invalid_filename", body)
	}
	e.wantNoVersion("myapp", "1.0.0", "отказ до чтения тела")
	e.wantNoTmpLeftovers("отказ до чтения тела: временный файл не заводился")

	// Контроль: годное имя при том же «тело не отправлено» ответа не даёт —
	// значит первая половина проверила именно порядок, а не то, что сервер
	// отвечает на что угодно, не читая.
	if st, _ := headersOnly(e, "2.0.0", "myapp-2.0.0.tar.gz", 300*time.Millisecond); st != "" {
		t.Errorf("годное имя ответило %q, не прочитав тела — тест ничего не меряет", st)
	}
	// Оборванная контрольная загрузка убирает за собой временный файл; ждём,
	// иначе t.TempDir снесёт каталог из-под хендлера.
	if left := e.waitTmpDrained(5 * time.Second); len(left) != 0 {
		t.Errorf("после обрыва контрольной загрузки в .tmp остались файлы: %v", left)
	}
}
