package integration

// T22: прогресс загрузки в веб-интерфейсе. Go-тесты выполняют ровно тот путь,
// который обязан пережить отсутствие JS: обычный multipart-POST по адресу из
// формы. Сам скрипт здесь не исполняется — проверяется, что он не отобрал у
// формы ничего из того, чем она работала раньше, и что разметка прогресса
// доехала до страницы целой. Задача R7-test.

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// appPage fetches the app page of a logged-in client.
func (e *env) appPage(c *http.Client, app string) string {
	e.t.Helper()
	return e.uiPageBody(c, "/apps/"+url.PathEscape(app), http.StatusOK)
}

// uploadFormOf cuts the upload form out of the app page.
func uploadFormOf(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, `<form id="upload-form"`)
	if i < 0 {
		t.Fatalf("на странице нет формы загрузки")
	}
	j := strings.Index(page[i:], "</form>")
	if j < 0 {
		t.Fatal("форма загрузки не закрыта")
	}
	return page[i : i+j]
}

// TestUploadFormWorksWithoutJavaScript: полный сквозной сценарий без единой
// строки JS — вход, страница, обычный multipart-POST, 303, файл на диске и
// скачивание. Именно этот путь остаётся у пользователя с выключенным JS.
func TestUploadFormWorksWithoutJavaScript(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	page := e.appPage(c, "myapp")
	form := uploadFormOf(t, page)

	// Форма осталась обычной: без method/action/enctype браузер без JS не
	// отправит ничего осмысленного.
	for _, want := range []string{
		`method="post"`,
		`enctype="multipart/form-data"`,
		`action="/apps/myapp/versions"`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("форма потеряла %q — без JS отправка сломана:\n%s", want, form)
		}
	}

	archive := tarGzBytes(t, multiFileRelease())
	resp := e.uploadUI(c, "myapp", "1.0.0", sha256hex(archive), "myapp-1.0.0.tar.gz", archive, e.csrfOf(c))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST без JS: status = %d, want 303; body: %s", resp.StatusCode, readBody(t, resp))
	}
	if loc := resp.Header.Get("Location"); loc != "/apps/myapp" {
		t.Errorf("Location = %q, want /apps/myapp", loc)
	}
	_, _, got := e.downloadFull("myapp", "1.0.0")
	wantSameEntries(t, unTarGz(t, got), multiFileRelease(), "архив, залитый формой без JS")
	e.assertNoDanglingRows()
}

// TestUploadFormPartOrderIsEnforcedEndToEnd: file обязан идти последним —
// хендлер читает части потоково и к моменту файла должен иметь csrf_token.
// Проверяется и разметкой (порядок полей), и поведением: тот же POST с file
// впереди CSRF отвергается, а не проглатывается молча.
func TestUploadFormPartOrderIsEnforcedEndToEnd(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	form := uploadFormOf(t, e.appPage(c, "myapp"))

	var names []string
	for _, m := range regexp.MustCompile(`name="([^"]+)"`).FindAllStringSubmatch(form, -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatalf("в форме нет именованных полей:\n%s", form)
	}
	if last := names[len(names)-1]; last != "file" {
		t.Errorf("последнее поле формы = %q, want \"file\" (порядок: %v)", last, names)
	}

	// Обратная сторона инварианта: file впереди — CSRF ещё не прочитан, отказ.
	body := fileFirstBody(t, e.csrfOf(c), "1.0.0", "myapp-1.0.0.tar.gz", []byte("payload"))
	resp := e.postRaw(c, "/apps/myapp/versions", body.ctype, body.body)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Error("загрузка с file впереди csrf_token принята — инвариант порядка частей не защищён")
	}
	e.wantNoVersion("myapp", "1.0.0", "file впереди csrf_token")
}

// TestUploadFormRejectsMissingCSRF: double-submit на месте — форма без токена
// отвергается, а версия не создаётся. Скрипт T22 шлёт ту же FormData, значит
// он опирается ровно на этот токен.
func TestUploadFormRejectsMissingCSRF(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	e.appPage(c, "myapp")

	archive := tarGzBytes(t, multiFileRelease())
	for _, tc := range []struct{ name, token string }{
		{"empty_token", ""},
		{"wrong_token", "not-the-cookie-value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.uploadUI(c, "myapp", "1.0.0", "", "myapp-1.0.0.tar.gz", archive, tc.token)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403; body: %s", resp.StatusCode, readBody(t, resp))
			}
			e.wantNoVersion("myapp", "1.0.0", "загрузка без годного CSRF-токена")
		})
	}
}

// TestProgressMarkupPresentAndInline: элементы прогресса и кнопка отмены есть
// на странице, скрипт inline и наружу ничего не тянет. Проект ставится в
// закрытые контуры — внешний src сделал бы прогресс неработающим молча.
func TestProgressMarkupPresentAndInline(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	page := e.appPage(c, "myapp")

	for _, want := range []string{
		`<progress id="upload-bar"`,                       // полоса
		`<span id="upload-percent"`,                       // процент и объём
		`<p id="upload-progress" hidden>`,                 // скрыта, пока нет JS
		`<p id="upload-failed" class="error" hidden`,      // сообщение об обрыве
		`<button type="button" id="upload-abort" hidden>`, // кнопка отмены
		`id="upload-submit"`,                              // кнопка отправки, которую скрипт прячет
		"upload.onprogress",                               // собственно прогресс
		"xhr.abort()",                                     // отмена
	} {
		if !strings.Contains(page, want) {
			t.Errorf("на странице приложения нет %q", want)
		}
	}

	// Внешних ресурсов нет ни в каком виде.
	for _, bad := range []string{"<script src", "<link rel=\"stylesheet\" href=\"http", "//cdn.", "https://unpkg", "integrity="} {
		if strings.Contains(page, bad) {
			t.Errorf("страница тянет внешний ресурс (%q)", bad)
		}
	}
}

// TestProgressMarkupSurvivesEscaping: описание приложения попадает на ту же
// страницу, что и скрипт. Если бы его вставляли без экранирования, описание с
// </script> закрывало бы блок скрипта и убивало прогресс — а заодно открывало
// XSS. Проверяется, что описание экранировано, а скрипт и форма целы.
func TestProgressMarkupSurvivesEscaping(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	const nasty = `</script><script>window.__pwned=1</script>"'&<progress id="upload-bar">`
	body, err := jsonBody(map[string]string{"name": "myapp", "description": nasty})
	if err != nil {
		t.Fatal(err)
	}
	resp := e.api("POST", "/api/apps", strings.NewReader(body), jsonHdr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("создание приложения с описанием-инъекцией: status = %d, want 201", resp.StatusCode)
	}

	c := e.uiClient()
	e.login(c, "/")
	page := e.appPage(c, "myapp")

	// Сырая инъекция не должна встречаться на странице ни в каком виде.
	if strings.Contains(page, "window.__pwned=1</script>") || strings.Contains(page, "</script><script>") {
		t.Errorf("описание вставлено без экранирования — разметка скрипта сломана")
	}
	// Экранированный след при этом обязан быть: описание не потеряно.
	if !strings.Contains(page, "&lt;/script&gt;") && !strings.Contains(page, "\\u003c/script\\u003e") {
		t.Errorf("описание с разметкой не отобразилось экранированным")
	}
	// Форма и скрипт прогресса на месте и не разорваны.
	form := uploadFormOf(t, page)
	if !strings.Contains(form, `enctype="multipart/form-data"`) {
		t.Error("форма загрузки повреждена описанием-инъекцией")
	}
	if !strings.Contains(page, "upload.onprogress") || !strings.Contains(page, "xhr.abort()") {
		t.Error("скрипт прогресса повреждён описанием-инъекцией")
	}
	// Ровно один элемент прогресса — подставленный шаблоном, а не описанием.
	if n := strings.Count(page, `<progress id="upload-bar"`); n != 1 {
		t.Errorf("элементов <progress id=\"upload-bar\"> на странице %d, want 1", n)
	}
}

// TestUploadFormAbsentWithoutPermission: у роли без права заливать версии
// формы (а с ней и скрипта) на странице нет — прогресс не должен протаскивать
// разметку мимо проверки прав.
func TestUploadFormAbsentWithoutPermission(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	viewer := e.mkUser("viewer", validPass, "deployer")

	// deployer входит, но в UI не допущен вовсе — проверяем через API-роль,
	// у которой UI есть: maintainer видит форму, а вот developer-минус нет.
	c, code := e.loginAs(viewer, "/")
	if code != http.StatusSeeOther {
		t.Fatalf("вход deployer: status = %d, want 303", code)
	}
	status, body := e.uiStatus(c, "/apps/myapp")
	if status == http.StatusOK && strings.Contains(body, `id="upload-form"`) {
		t.Error("роль без права на версии видит форму загрузки")
	}
	if status == http.StatusOK && strings.Contains(body, "upload.onprogress") {
		t.Error("роль без права на версии получает скрипт загрузки")
	}
}

// fileFirstBody builds a multipart body with the file part FIRST — the order
// the template forbids. Отрицательный контроль инварианта: без него тест на
// порядок полей проверял бы только разметку и зеленел бы на хендлере, которому
// порядок безразличен.
func fileFirstBody(t *testing.T, csrf, version, filename string, payload []byte) rawBody {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	for _, f := range []struct{ k, v string }{
		{"csrf_token", csrf}, {"version", version}, {"sha256", ""},
	} {
		if err := mw.WriteField(f.k, f.v); err != nil {
			t.Fatalf("WriteField %s: %v", f.k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	return rawBody{body: buf.Bytes(), ctype: mw.FormDataContentType()}
}
