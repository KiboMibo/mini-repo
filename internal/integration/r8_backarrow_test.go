package integration

// Стрелка «назад» (T26): на страницах ниже корневого списка — обычная ссылка
// на `/`. Проверяется на живом сервере, а не только в шаблоне: страница
// собирается из layout + content, и потеряться стрелка может при склейке.
// Задача R8-test; ассерт глифа перевязан к элементу в R9-test.

import (
	"regexp"
	"strings"
	"testing"
)

// anchorRe разбирает якоря страницы на атрибуты и текст. Через него ищется
// стрелка: атрибуты и глиф обязаны принадлежать ОДНОМУ элементу.
//
// Почему не `strings.Contains(body, ">&lt;</a>")`: имя файла версии "<"
// проходит naming.ValidateFilename и уезжает в ссылку скачивания как
// `<a href="/download/…">&lt;</a>` — такой ассерт зеленеет от чужого якоря,
// даже если стрелку из шаблона убрать совсем (R9-test, проверено мутацией).
var anchorRe = regexp.MustCompile(`(?s)<a\b([^>]*)>(.*?)</a>`)

// backAnchor возвращает атрибуты и текст стрелки «назад». Порядок атрибутов
// не важен — их перестановка поведения не меняет и падением быть не должна.
func backAnchor(body string) (attrs, text string, ok bool) {
	for _, m := range anchorRe.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], `class="back"`) && strings.Contains(m[1], `href="/"`) {
			return m[1], m[2], true
		}
	}
	return "", "", false
}

func TestBackArrowOnPagesBelowRoot(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("arrow")
	e.seed("arrow", "1.0.0")

	below := []string{"/apps/arrow", "/users"}
	for _, path := range below {
		t.Run("есть_на_"+path, func(t *testing.T) {
			body := e.getPage(c, path)
			attrs, text, ok := backAnchor(body)
			if !ok {
				t.Fatalf("на %s нет ссылки-стрелки с class=\"back\" на /", path)
			}
			if text != "&lt;" {
				t.Errorf("на %s глиф стрелки = %q, want %q", path, text, "&lt;")
			}
			// Глиф "<" сам по себе экранному диктору ничего не говорит —
			// назначение ссылки несёт только подпись.
			if !strings.Contains(attrs, `aria-label="Back to applications"`) {
				t.Errorf("на %s у стрелки нет aria-label; атрибуты: %s", path, attrs)
			}
			// Прогрессивное улучшение здесь ни при чём: без JS страница
			// обязана работать так же, поэтому ни onclick, ни history.
			if strings.Contains(attrs, "onclick") {
				t.Errorf("на %s стрелка сделана скриптом; атрибуты: %s", path, attrs)
			}
			for _, bad := range []string{"history.back", "history.go", `class="back" onclick`} {
				if strings.Contains(body, bad) {
					t.Errorf("на %s стрелка сделана скриптом (%s), а не ссылкой", path, bad)
				}
			}
		})
	}

	t.Run("нет_на_корневой", func(t *testing.T) {
		body := e.getPage(c, "/")
		if _, _, ok := backAnchor(body); ok {
			t.Errorf("на корневом списке есть стрелка «назад» — возвращаться некуда")
		}
	})

	t.Run("ведёт_на_список_приложений", func(t *testing.T) {
		// Переход по стрелке — обычный GET того же клиента: страница обязана
		// открыться и показать приложение, а не редирект на вход.
		body := e.getPage(c, "/")
		if !strings.Contains(body, "arrow") {
			t.Errorf("после перехода по стрелке нет приложения в списке; body: %s", firstLines(body))
		}
	})
}
