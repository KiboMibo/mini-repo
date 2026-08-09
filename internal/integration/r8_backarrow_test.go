package integration

// Стрелка «назад» (T26): на страницах ниже корневого списка — обычная ссылка
// на `/`. Проверяется на живом сервере, а не только в шаблоне: страница
// собирается из layout + content, и потеряться стрелка может при склейке.
// Задача R8-test.

import (
	"regexp"
	"strings"
	"testing"
)

// backLink находит элемент стрелки на странице. Ищется класс и адрес вместе:
// «где-то есть ссылка на /» на любой странице правда и ничего не доказывает.
var backLink = regexp.MustCompile(`<a[^>]*class="back"[^>]*href="/"[^>]*>|<a[^>]*href="/"[^>]*class="back"[^>]*>`)

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
			if !backLink.MatchString(body) {
				t.Errorf("на %s нет ссылки-стрелки с class=\"back\" на /", path)
			}
			if !strings.Contains(body, ">&lt;</a>") {
				t.Errorf("на %s стрелка не нарисована (&lt;)", path)
			}
			// Прогрессивное улучшение здесь ни при чём: без JS страница
			// обязана работать так же, поэтому ни onclick, ни history.
			for _, bad := range []string{"history.back", "history.go", `class="back" onclick`} {
				if strings.Contains(body, bad) {
					t.Errorf("на %s стрелка сделана скриптом (%s), а не ссылкой", path, bad)
				}
			}
		})
	}

	t.Run("нет_на_корневой", func(t *testing.T) {
		body := e.getPage(c, "/")
		if backLink.MatchString(body) {
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
