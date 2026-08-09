package integration

// Архивы: в .tar.gz и .zip определять платформу нечего, поэтому волна 8
// требует называть её явно. Проверяется в обоих интерфейсах и по обоим
// форматам, вместе с состоянием диска: отказ обязан не оставлять ни строки в
// БД, ни файла в каталоге версии, ни мусора в .tmp.
// Задача R8-test.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// archiveKind — формат архива и его расширение.
type archiveKind struct {
	name string
	ext  string
	make func(t *testing.T, entries []archiveEntry) []byte
}

var archiveKinds = []archiveKind{
	{"tar.gz", ".tar.gz", tarGzBytes},
	{"zip", ".zip", zipBytes},
}

// TestArchiveWithoutPlatformRefusedByAPI: 400 platform_required, ничего не
// сохранено. Текст отказа читает лог сломавшегося пайплайна, поэтому он обязан
// оставаться самодостаточным — в нём и "any", и готовая строка curl.
func TestArchiveWithoutPlatformRefusedByAPI(t *testing.T) {
	e := newEnv(t, r8MaxUpload)
	e.createApp("arch")

	for _, k := range archiveKinds {
		t.Run(k.name, func(t *testing.T) {
			body := k.make(t, multiFileRelease())
			name := "arch-1.0.0" + k.ext
			resp := e.putWithPlatform("arch", "1.0.0", name, "", body)
			text := readBody(t, resp)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s без платформы: status = %d, want 400; body: %s", k.name, resp.StatusCode, text)
			}
			if !strings.Contains(text, `"platform_required"`) {
				t.Errorf("код ошибки не platform_required; body: %s", text)
			}
			// Смотрим в разобранное сообщение, а не в сырое тело: кавычки
			// вокруг "any" в JSON экранированы, и поиск по телу их не найдёт.
			msg := jsonField(t, text, "message")
			for _, want := range []string{`"any"`, "curl", "platform=linux/amd64", name} {
				if !strings.Contains(msg, want) {
					t.Errorf("в тексте отказа нет %q — по логу CI непонятно, как чинить; message: %s", want, msg)
				}
			}
			e.wantNoVersion("arch", "1.0.0", k.name+" без платформы через API")
		})
	}
}

// TestArchiveWithoutPlatformRefusedByUI: то же в интерфейсе — 400 с понятным
// человеку текстом, версии нет, файл убран, .tmp пуст. Класс кода тот же, что
// в API (инвариант «одна ошибка — один класс кода в обоих интерфейсах»).
func TestArchiveWithoutPlatformRefusedByUI(t *testing.T) {
	e := newEnv(t, r8MaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("archui")

	for _, k := range archiveKinds {
		t.Run(k.name, func(t *testing.T) {
			body := k.make(t, multiFileRelease())
			resp := e.uploadUIPlatform(c, "archui", "1.0.0", "archui-1.0.0"+k.ext, body, "", "")
			text := readBody(t, resp)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s без платформы через UI: status = %d, want 400; body: %s",
					k.name, resp.StatusCode, firstLines(text))
			}
			if !strings.Contains(text, "could not tell from the file") {
				t.Errorf("страница не объясняет, почему отказ; body: %s", firstLines(text))
			}
			e.wantNoVersion("archui", "1.0.0", k.name+" без платформы через UI")
		})
	}
}

// TestArchiveWithExplicitPlatformAccepted: тот же архив с явной платформой —
// 201/303, и метка ровно та, что назвали. Без этого теста отказ выше читался бы
// как «архивы больше не принимаются».
func TestArchiveWithExplicitPlatformAccepted(t *testing.T) {
	e := newEnv(t, r8MaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("archok")

	cases := []struct {
		name     string
		plat     string
		os, arch string
	}{
		{"any", "any", "any", ""},
		{"явная пара", "linux/amd64", "linux", "amd64"},
	}
	n := 0
	for _, k := range archiveKinds {
		for _, tc := range cases {
			t.Run(k.name+"/"+tc.name, func(t *testing.T) {
				body := k.make(t, multiFileRelease())
				n++
				apiVersion, uiVersion := nthVersion(2*n), nthVersion(2*n+1)

				resp := e.putWithPlatform("archok", apiVersion,
					"api-"+apiVersion+k.ext, tc.plat, body)
				text := readBody(t, resp)
				resp.Body.Close()
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("API: status = %d, want 201; body: %s", resp.StatusCode, text)
				}
				e.wantPlatformEverywhere(c, "archok", apiVersion, tc.plat, "архив с ?platform="+tc.plat)

				resp = e.uploadUIPlatform(c, "archok", uiVersion,
					"ui-"+uiVersion+k.ext, body, tc.os, tc.arch)
				text = readBody(t, resp)
				resp.Body.Close()
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("UI: status = %d, want 303; body: %s", resp.StatusCode, firstLines(text))
				}
				e.wantPlatformEverywhere(c, "archok", uiVersion, tc.plat, "архив с парой из формы")

				// Содержимое обязано остаться архивом: платформа — метка, а не
				// повод трогать байты.
				if got := e.mustDownload("archok", apiVersion); len(got) != len(body) {
					t.Errorf("скачано %d байт, залито %d", len(got), len(body))
				}
			})
		}
	}
}

// TestInvalidPlatformRefusedBeforeBody: мусор в ?platform= — 400
// invalid_platform, и, как у ?filename= (F19), отказ обязан стоить клиенту ноль
// байтов тела: на двухгигабайтном архиве иначе это два гигабайта трафика ради
// 400. Способ тот же — запрос с объявленным телом, которого сервер не получит.
func TestInvalidPlatformRefusedBeforeBody(t *testing.T) {
	e := newEnv(t, r8MaxUpload)
	e.createApp("early")

	status, text := e.putHeadersOnly(
		"/api/apps/early/versions/1.0.0?filename=early-bin&platform=amd64", 5*time.Second)
	if !strings.Contains(status, "400") {
		t.Fatalf("отказ по платформе не пришёл до тела: status line = %q", status)
	}
	if !strings.Contains(text, `"invalid_platform"`) {
		t.Errorf("код ошибки не invalid_platform; body: %s", text)
	}
	// Текст показывается пользователю как есть и обязан перечислять словарь.
	for _, want := range []string{"linux", "amd64", "any"} {
		if !strings.Contains(text, want) {
			t.Errorf("в тексте отказа нет %q; body: %s", want, text)
		}
	}
	e.wantNoVersion("early", "1.0.0", "после 400 invalid_platform")

	// Контроль: тот же запрос с годной платформой ответа без тела не даёт —
	// значит проверено именно место валидации, а не «сервер отвечает всегда».
	if st, _ := e.putHeadersOnly(
		"/api/apps/early/versions/2.0.0?filename=early-bin&platform=linux/amd64",
		300*time.Millisecond); st != "" {
		t.Errorf("годная платформа ответила %q, не прочитав тела — тест ничего не меряет", st)
	}
	if left := e.waitTmpDrained(5 * time.Second); len(left) != 0 {
		t.Errorf("после обрыва контрольной загрузки в .tmp остались файлы: %v", left)
	}
}
