package web_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// uploadForm вырезает разметку формы загрузки со страницы приложения.
func uploadForm(t *testing.T, e *env, app string) string {
	t.Helper()
	rec := e.do(t, "GET", "/apps/"+app, "", nil, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /apps/%s: code = %d", app, rec.Code)
	}
	body := rec.Body.String()
	i := strings.Index(body, `<form id="upload-form"`)
	if i < 0 {
		t.Fatalf("на странице нет формы загрузки:\n%s", body)
	}
	j := strings.Index(body[i:], "</form>")
	if j < 0 {
		t.Fatal("форма загрузки не закрыта")
	}
	return body[i : i+j]
}

// T22: порядок частей multipart — записанный инвариант проекта (хендлер читает
// поток и к моменту файла обязан иметь csrf_token/version/sha256). Скрипт
// собирает FormData из этой же формы, а FormData обходит поля в порядке
// разметки — значит инвариант держится разметкой, и его стережёт этот тест.
func TestUploadFormFileFieldIsLast(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	form := uploadForm(t, e, "myapp")

	var names []string
	for _, m := range regexp.MustCompile(`name="([^"]+)"`).FindAllStringSubmatch(form, -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatalf("в форме нет именованных полей:\n%s", form)
	}
	if last := names[len(names)-1]; last != "file" {
		t.Errorf("последнее поле формы = %q, want \"file\" (порядок частей: %v)", last, names)
	}
	// Три поля, которые хендлер обязан получить до файла.
	for _, want := range []string{"csrf_token", "version", "sha256"} {
		pos, filePos := -1, -1
		for i, n := range names {
			if n == want && pos < 0 {
				pos = i
			}
			if n == "file" {
				filePos = i
			}
		}
		if pos < 0 {
			t.Errorf("поле %q пропало из формы загрузки", want)
			continue
		}
		if pos > filePos {
			t.Errorf("поле %q идёт после file (порядок: %v)", want, names)
		}
	}
}

// T22: CSRF-токен по-прежнему уезжает скрытым полем в теле формы — на нём
// держится double-submit, и XHR шлёт ровно то же тело.
func TestUploadFormKeepsCSRFField(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	form := uploadForm(t, e, "myapp")
	if !strings.Contains(form, `<input type="hidden" name="csrf_token" value=`) {
		t.Errorf("в форме загрузки нет скрытого поля csrf_token:\n%s", form)
	}
}

// T22: разметка прогресса и кнопка отмены присутствуют, а без JS не мешают —
// форма остаётся обычной multipart-формой, элементы прогресса скрыты.
func TestUploadFormProgressMarkup(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	form := uploadForm(t, e, "myapp")
	for _, want := range []string{
		`method="post"`,                                              // без JS — обычная отправка
		`enctype="multipart/form-data"`,                              //
		`action="/apps/myapp/versions"`,                              // тот же адрес, что и у XHR
		`<progress id="upload-bar"`,                                  // полоса
		`<span id="upload-percent"`,                                  // процент и объём
		`<p id="upload-progress" hidden>`,                            // по умолчанию скрыта
		`<p id="upload-failed" class="error" hidden`,                 // сообщение об обрыве
		`<button type="button" id="upload-abort" hidden>`,            // кнопка отмены
		`<button formmethod="dialog" formnovalidate>Cancel</button>`, // закрытие модалки без JS
	} {
		if !strings.Contains(form, want) {
			t.Errorf("в форме загрузки нет %q:\n%s", want, form)
		}
	}
}

// T22: скрипт прогресса — inline, без внешних ресурсов. Проект собирается в
// один бинарник и ставится в закрытые контуры: src/href наружу недопустимы.
func TestUploadScriptHasNoExternalResources(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "GET", "/apps/myapp", "", nil, false)
	body := rec.Body.String()
	if !strings.Contains(body, "upload.onprogress") {
		t.Error("на странице нет скрипта прогресса (upload.onprogress)")
	}
	if strings.Contains(body, "<script src") || strings.Contains(body, "//cdn.") {
		t.Errorf("страница тянет внешний ресурс:\n%s", body)
	}
}

// T22: базовый сценарий без JS не изменился — обычный multipart POST по адресу
// из формы кладёт версию на диск и в БД.
func TestUploadWithoutJavaScriptStillWorks(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	body, ctype := multipartBody(t, map[string]string{
		"csrf_token": csrfTok, "version": "1.0.0", "platform_os": "any",
	}, "myapp-bin", []byte("payload"))
	rec := e.do(t, "POST", "/apps/myapp/versions", ctype, body, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/apps/myapp" {
		t.Errorf("Location = %q, want /apps/myapp", loc)
	}
	v, err := e.st.GetVersion(app.ID, "1.0.0")
	if err != nil || v == nil {
		t.Fatalf("версия не создана: %v %v", v, err)
	}
	if !exists(t, e.fs.Path("myapp", "1.0.0", "myapp-bin")) {
		t.Error("файл версии не лёг на диск")
	}
}
