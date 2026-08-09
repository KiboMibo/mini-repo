package web_test

// Задача F22: словарь платформ целиком в internal/platform (особые значения
// тоже) и возврат введённого в диалог после отказа.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"apprepo/internal/platform"
)

// TestTemplatesHaveNoPlatformLiterals: разметка не знает ни одного значения
// словаря наизусть. `any` и `darwin/universal` были вписаны литералами, и
// переименование или отмена константы прошли бы мимо шаблона молча
// (R8-sec круг 2, N3).
func TestTemplatesHaveNoPlatformLiterals(t *testing.T) {
	files, err := filepath.Glob("templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("шаблоны не найдены: %v", err)
	}
	// Проверяются особые значения: имена ОС и архитектур — обычные слова
	// ("any" сюда же не годится как подстрока, поэтому ищем как значение
	// атрибута), и ложные срабатывания на прозе комментариев не нужны.
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, lit := range []string{
			`value="` + platform.Universal + `"`,
			`value="` + platform.Any + `"`,
		} {
			if strings.Contains(string(b), lit) {
				t.Errorf("%s: значение словаря вписано литералом (%s) — берите его из view.PlatformSpecial", f, lit)
			}
		}
	}
}

// TestSpecialPlatformsRendered: обратная сторона — оба особых значения на
// странице всё-таки есть, и оба принимаются Parse.
func TestSpecialPlatformsRendered(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "archive.tar.gz", "payload")
	page := e.do(t, "GET", "/apps/myapp", "", nil, false).Body.String()
	for _, special := range []string{platform.Any, platform.Universal} {
		if _, err := platform.Parse(special); err != nil {
			t.Errorf("особое значение %q не проходит Parse: %v", special, err)
		}
		// По одному пункту в форме заливки и в диалоге строки.
		if n := strings.Count(page, `value="`+special+`"`); n != 2 {
			t.Errorf("вариант %q встречается %d раз, want 2 (форма заливки и диалог версии)", special, n)
		}
	}
}

// TestPlatformDialogKeepsSubmittedValue: после отказа диалог открывается с тем,
// что отправили, а не с сохранённым значением — так же ведёт себя форма
// заливки (R8-qa, замечание 4). Иначе «выбрал windows, забыл архитектуру,
// получил 400» стоит выбора заново.
func TestPlatformDialogKeepsSubmittedValue(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "archive.tar.gz", "payload")
	// Сохранённое значение — заведомо другое: если в ответе окажется оно,
	// значит отправленное потерялось.
	v, err := e.st.GetVersion(app.ID, "1.0.0")
	if err != nil || v == nil {
		t.Fatalf("GetVersion: %v %v", v, err)
	}
	if err := e.st.SetVersionPlatform(v.ID, "linux/arm64"); err != nil {
		t.Fatal(err)
	}

	body, ctype := form(map[string]string{
		"csrf_token": csrfTok, "platform_os": "windows", "platform_arch": ""})
	rec := e.do(t, "POST", "/apps/myapp/versions/1.0.0/platform", ctype, body, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, `<option value="windows" selected>`) {
		t.Errorf("в диалоге не выбрано отправленное windows; body: %s", page)
	}
	for _, lost := range []string{`<option value="linux" selected>`, `<option value="arm64" selected>`} {
		if strings.Contains(page, lost) {
			t.Errorf("в диалоге показано сохранённое значение %q вместо отправленного", lost)
		}
	}
}
