package web_test

// T26: стрелка «назад» на страницах ниже корня и платформа версии в интерфейсе —
// колонка в таблице, поле в форме загрузки, ручная простановка у строки.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"apprepo/internal/auth"
	"apprepo/internal/platform"
)

// backLink — разметка стрелки; по ней тесты отличают её от ссылки «apprepo» в
// шапке, которая тоже ведёт на "/" и на корневой странице остаётся.
const backLink = `<a class="back" href="/"`

// TestBackArrowOnPagesBelowRoot: стрелка есть там, где заголовок не корневой, и
// это обычная ссылка на "/" — без JS и без history.back().
func TestBackArrowOnPagesBelowRoot(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"/apps/myapp", "/users"} {
		rec := e.do(t, "GET", page, "", nil, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: code = %d", page, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, backLink) {
			t.Errorf("на %s нет стрелки назад (%s)", page, backLink)
		}
		if !strings.Contains(body, `aria-label="Back to applications">&lt;</a>`) {
			t.Errorf("на %s стрелка не нарисована символом <", page)
		}
		// Никакой истории браузера: ссылка работает без JS и в новой вкладке.
		for _, js := range []string{"history.back", "history.go"} {
			if strings.Contains(body, js) {
				t.Errorf("на %s возврат сделан через %s, а не ссылкой", page, js)
			}
		}
	}
	// Корневой список — верхний раздел, возвращаться некуда.
	if body := e.do(t, "GET", "/", "", nil, false).Body.String(); strings.Contains(body, backLink) {
		t.Error("на корневой странице есть стрелка назад")
	}
}

// TestVersionsTableShowsPlatform: значение показывается как есть, а пустое —
// видимым прочерком, чтобы «неизвестно, можно проставить» было заметно.
func TestVersionsTableShowsPlatform(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "bin", "payload")
	e.addVersion(t, app, "2.0.0", "archive.tar.gz", "payload")
	v, _ := e.st.GetVersion(app.ID, "1.0.0")
	if err := e.st.SetVersionPlatform(v.ID, "linux/amd64"); err != nil {
		t.Fatal(err)
	}

	body := e.do(t, "GET", "/apps/myapp", "", nil, false).Body.String()
	for _, want := range []string{
		"<th>Platform</th>",
		"<code>linux/amd64</code>",
		`<td class="muted" title="Unknown`, // прочерк у версии без платформы
	} {
		if !strings.Contains(body, want) {
			t.Errorf("на странице нет %q", want)
		}
	}
}

// TestUploadFormPlatformComesFromDictionary: списки собираются из
// platform.KnownOS()/KnownArch(), а не перечислением в разметке — иначе форма
// разъедется со словарём, который проверяет platform.Parse.
func TestUploadFormPlatformComesFromDictionary(t *testing.T) {
	e := newEnv(t)
	if _, err := e.st.CreateApp("myapp", ""); err != nil {
		t.Fatal(err)
	}
	form := uploadForm(t, e, "myapp")

	for _, goos := range platform.KnownOS() {
		if !strings.Contains(form, `<option value="`+goos+`">`) {
			t.Errorf("в форме нет ОС %q из KnownOS()", goos)
		}
	}
	for _, goarch := range platform.KnownArch() {
		if !strings.Contains(form, `<option value="`+goarch+`">`) {
			t.Errorf("в форме нет архитектуры %q из KnownArch()", goarch)
		}
	}
	// Обратная сторона: ничего сверх словаря, кроме "" (определить самим).
	// Половинки пары по отдельности через Parse не проходят, поэтому список
	// допустимого собирается из самого словаря плюс особые значения, которые
	// Parse принимает целиком (any, darwin/universal — F21).
	allowed := map[string]bool{"": true}
	for _, s := range append(platform.KnownOS(), platform.KnownArch()...) {
		allowed[s] = true
	}
	for _, m := range regexp.MustCompile(`<option value="([^"]*)"`).FindAllStringSubmatch(form, -1) {
		if _, err := platform.Parse(m[1]); err == nil {
			continue // особое значение целиком (any, darwin/universal)
		}
		if !allowed[m[1]] {
			t.Errorf("в форме есть вариант %q, которого нет в словаре platform", m[1])
		}
	}
	// Оба поля на месте и оба — до файла (порядок частей стережёт T22-тест).
	for _, want := range []string{`name="platform_os"`, `name="platform_arch"`} {
		if !strings.Contains(form, want) {
			t.Errorf("в форме загрузки нет поля %s", want)
		}
	}
}

// elfAmd64 — минимальный валидный заголовок ELF64 linux/amd64: platform.Detect
// читает только заголовок, поэтому тела файлу не нужно.
func elfAmd64() []byte {
	var buf bytes.Buffer
	ident := make([]byte, 16)
	copy(ident, elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	buf.Write(ident)
	put := func(v any) { binary.Write(&buf, binary.LittleEndian, v) }
	put(uint16(elf.ET_EXEC))
	put(uint16(elf.EM_X86_64))
	put(uint32(elf.EV_CURRENT))
	put(uint64(0)) // entry
	put(uint64(0)) // phoff
	put(uint64(0)) // shoff
	put(uint32(0)) // flags
	put(uint16(64))
	for i := 0; i < 5; i++ { // phentsize, phnum, shentsize, shnum, shstrndx
		put(uint16(0))
	}
	return buf.Bytes()
}

// uploadVersion заливает версию через форму интерфейса с заданными полями.
func (e *env) uploadVersion(t *testing.T, app, version string, fields map[string]string, content []byte) *http.Response {
	t.Helper()
	all := map[string]string{"csrf_token": csrfTok, "version": version}
	for k, v := range fields {
		all[k] = v
	}
	body, ctype := multipartBody(t, all, "payload.bin", content)
	return e.do(t, "POST", "/apps/"+app+"/versions", ctype, body, true).Result()
}

// TestUploadDetectsPlatform: у обычного бинарника платформу не спрашивают —
// она читается из файла.
func TestUploadDetectsPlatform(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	resp := e.uploadVersion(t, "myapp", "1.0.0", nil, elfAmd64())
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", resp.StatusCode)
	}
	if v, _ := e.st.GetVersion(app.ID, "1.0.0"); v == nil || v.Platform != "linux/amd64" {
		t.Fatalf("Platform = %+v, want linux/amd64", v)
	}
}

// TestUploadArchiveWithoutPlatformRefused: определять в архиве нечего —
// понятный отказ на странице (не 500), открытая модалка и ничего на диске.
func TestUploadArchiveWithoutPlatformRefused(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	resp := e.uploadVersion(t, "myapp", "1.0.0", nil, []byte("not a binary at all"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", resp.StatusCode)
	}
	body := readAll(t, resp)
	for _, want := range []string{
		`<p class="error">`,            // баннер, а не «internal server error»
		"could not tell from the file", // человеческий текст
		"Nothing was stored.",
		`<dialog id="upload-dialog" open>`, // форма остаётся открытой
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в ответе нет %q; body: %s", want, body)
		}
	}
	if v, _ := e.st.GetVersion(app.ID, "1.0.0"); v != nil {
		t.Error("версия создана, хотя платформа неизвестна")
	}
	if exists(t, e.fs.Path("myapp", "1.0.0", "payload.bin")) {
		t.Error("файл остался на диске после отказа")
	}
}

// TestUploadWithManualPlatform: указанная руками платформа принимается там, где
// по файлу определить нечего, а негодная пара отвергается до чтения тела.
//
// F21: подслучай «указанное перевешивает определённое» отсюда убран — контракт
// сменился. T26 давал руками указанной паре перевесить содержимое файла, а T25
// в API тот же случай отвергал (409 platform_mismatch); проверочная волна 8
// (R8-test, находка 1) назвала это расхождение блокирующим — один и тот же
// файл с той же меткой принимался в UI и отклонялся в API. Решение командира:
// везде отказ, потому что молчаливое расхождение метки и содержимого
// обнаруживает не заливающий, а тот, кто скачал артефакт. Новое поведение
// закреплено ниже в TestUploadPlatformMismatchRefused.
func TestUploadWithManualPlatform(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		version string
		fields  map[string]string
		content []byte
		want    string
	}{
		{name: "архив помечен any", version: "1.0.0",
			fields:  map[string]string{"platform_os": "any"},
			content: []byte("tar.gz"), want: platform.Any},
		// darwin/universal — особое значение рядом с any (F21/R8-sec S4):
		// у fat-бинарника пары «архитектура» нет, и вводится оно целиком.
		{name: "universal целиком", version: "1.5.0",
			fields:  map[string]string{"platform_os": platform.Universal},
			content: []byte("tar.gz"), want: platform.Universal},
		{name: "пара из списков", version: "2.0.0",
			fields:  map[string]string{"platform_os": "windows", "platform_arch": "arm64"},
			content: []byte("tar.gz"), want: "windows/arm64"},
		// Метка не спорит с содержимым: определить у ELF darwin нельзя было бы,
		// а вот совпадающая пара — законный случай (CI указывает то же, что в
		// файле, чтобы поймать сборку не под ту платформу).
		{name: "метка совпадает с содержимым", version: "3.0.0",
			fields:  map[string]string{"platform_os": "linux", "platform_arch": "amd64"},
			content: elfAmd64(), want: "linux/amd64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := e.uploadVersion(t, "myapp", c.version, c.fields, c.content)
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("code = %d, want 303; body: %s", resp.StatusCode, readAll(t, resp))
			}
			if v, _ := e.st.GetVersion(app.ID, c.version); v == nil || v.Platform != c.want {
				t.Fatalf("Platform = %+v, want %q", v, c.want)
			}
		})
	}

	// Половина пары — отказ с перечислением допустимых значений, версии нет.
	resp := e.uploadVersion(t, "myapp", "9.0.0",
		map[string]string{"platform_os": "linux"}, elfAmd64())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", resp.StatusCode)
	}
	if body := readAll(t, resp); !strings.Contains(body, "invalid platform") {
		t.Errorf("в ответе нет текста ошибки platform.Parse; body: %s", body)
	}
	if v, _ := e.st.GetVersion(app.ID, "9.0.0"); v != nil {
		t.Error("версия создана с негодной платформой")
	}
}

// TestUploadPlatformMismatchRefused: метка формы против содержимого файла — 409
// и ничего не сохранено, ровно как в API (R8-test, находка 1). Класс ответа на
// одну и ту же ошибку обязан совпадать в обоих интерфейсах.
func TestUploadPlatformMismatchRefused(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	resp := e.uploadVersion(t, "myapp", "1.0.0",
		map[string]string{"platform_os": "windows", "platform_arch": "amd64"}, elfAmd64())
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("code = %d, want 409; body: %s", resp.StatusCode, readAll(t, resp))
	}
	body := readAll(t, resp)
	for _, want := range []string{
		`<p class="error">`,
		"linux/amd64",   // что нашлось в файле
		"windows/amd64", // что сказала форма
		"nothing was stored",
		`<dialog id="upload-dialog" open>`, // модалка осталась открытой
		`name="version" required placeholder="1.2.3" value="1.0.0"`, // и поля в ней
		`<option value="windows" selected>windows</option>`,
		`<option value="amd64" selected>amd64</option>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в ответе нет %q; body: %s", want, body)
		}
	}
	if v, _ := e.st.GetVersion(app.ID, "1.0.0"); v != nil {
		t.Error("версия создана, хотя метка противоречит файлу")
	}
	if exists(t, e.fs.Path("myapp", "1.0.0", "payload.bin")) {
		t.Error("файл остался на диске после отказа")
	}
}

// TestSetVersionPlatformByHand: простановка у существующей версии и сброс
// обратно в «неизвестно» — сценарий архива, залитого раньше.
func TestSetVersionPlatformByHand(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "archive.tar.gz", "payload")
	set := func(t *testing.T, vals map[string]string) int {
		t.Helper()
		vals["csrf_token"] = csrfTok
		body, ctype := form(vals)
		return e.do(t, "POST", "/apps/myapp/versions/1.0.0/platform", ctype, body, true).Code
	}
	platformOf := func(t *testing.T) string {
		t.Helper()
		v, err := e.st.GetVersion(app.ID, "1.0.0")
		if err != nil || v == nil {
			t.Fatalf("GetVersion: %v %v", v, err)
		}
		return v.Platform
	}

	if code := set(t, map[string]string{"platform_os": "linux", "platform_arch": "arm64"}); code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", code)
	}
	if got := platformOf(t); got != "linux/arm64" {
		t.Fatalf("Platform = %q, want linux/arm64", got)
	}
	// Проставленное значение подставлено в списки строки.
	page := e.do(t, "GET", "/apps/myapp", "", nil, false).Body.String()
	for _, want := range []string{
		`action="/apps/myapp/versions/1.0.0/platform"`,
		`<option value="linux" selected>`,
		`<option value="arm64" selected>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("на странице нет %q", want)
		}
	}

	// any — отдельный вариант, архитектура при нём ни при чём.
	if code := set(t, map[string]string{"platform_os": "any", "platform_arch": "amd64"}); code != http.StatusSeeOther {
		t.Fatalf("any: code = %d, want 303", code)
	}
	if got := platformOf(t); got != platform.Any {
		t.Fatalf("Platform = %q, want %q", got, platform.Any)
	}

	// Сброс: пустая ОС возвращает «неизвестно».
	if code := set(t, map[string]string{"platform_os": "", "platform_arch": ""}); code != http.StatusSeeOther {
		t.Fatalf("сброс: code = %d, want 303", code)
	}
	if got := platformOf(t); got != "" {
		t.Fatalf("Platform after reset = %q, want empty", got)
	}

	// Негодная пара — 400 с текстом словаря и открытой модалкой строки.
	if code := set(t, map[string]string{"platform_os": "plan9", "platform_arch": "amd64"}); code != http.StatusBadRequest {
		t.Fatalf("мусор: code = %d, want 400", code)
	}
	body, ctype := form(map[string]string{"csrf_token": csrfTok, "platform_os": "plan9"})
	rec := e.do(t, "POST", "/apps/myapp/versions/1.0.0/platform", ctype, body, true)
	if !strings.Contains(rec.Body.String(), `<dialog id="plat-1.0.0" open>`) {
		t.Errorf("после отказа модалка строки закрыта; body: %s", rec.Body.String())
	}

	// Без CSRF — 403, значение не меняется.
	body, ctype = form(map[string]string{"platform_os": "linux", "platform_arch": "amd64"})
	if rec := e.do(t, "POST", "/apps/myapp/versions/1.0.0/platform", ctype, body, true); rec.Code != http.StatusForbidden {
		t.Fatalf("без поля csrf: code = %d, want 403", rec.Code)
	}
	if got := platformOf(t); got != "" {
		t.Fatalf("Platform after CSRF failure = %q, want empty", got)
	}

	// Несуществующая версия — 404, а не 500.
	if code := set(t, map[string]string{"platform_os": "linux", "platform_arch": "amd64"}); code != http.StatusSeeOther {
		t.Fatalf("подготовка: code = %d", code)
	}
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "platform_os": "linux", "platform_arch": "amd64"})
	if rec := e.do(t, "POST", "/apps/myapp/versions/7.7.7/platform", ctype, body, true); rec.Code != http.StatusNotFound {
		t.Fatalf("несуществующая версия: code = %d, want 404", rec.Code)
	}
}

// TestPlatformButtonHiddenWithoutPermission: кнопка простановки — под тем же
// правом, что и маршрут (deployer до страницы не доходит вовсе, см.
// TestRoutePermissionMatrix).
func TestPlatformButtonHiddenWithoutPermission(t *testing.T) {
	e := newEnv(t)
	app, err := e.st.CreateApp("myapp", "")
	if err != nil {
		t.Fatal(err)
	}
	e.addVersion(t, app, "1.0.0", "bin", "payload")
	_, sess := e.addUser(t, "nobody", auth.Role("reader"), "secret-pass") // роль вне матрицы: не может ничего
	if rec := e.doAs(t, sess, "GET", "/apps/myapp", "", nil, false); rec.Code != http.StatusForbidden {
		t.Fatalf("неизвестная роль: code = %d, want 403", rec.Code)
	}

	// developer право имеет — кнопка и форма на месте.
	_, dev := e.addUser(t, "dev", auth.RoleDeveloper, "secret-pass")
	body := e.doAs(t, dev, "GET", "/apps/myapp", "", nil, false).Body.String()
	if !strings.Contains(body, `action="/apps/myapp/versions/1.0.0/platform"`) {
		t.Error("developer не видит формы простановки платформы")
	}
}

// readAll читает тело ответа целиком.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
