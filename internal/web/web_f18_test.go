package web_test

// Сообщение об истёкшей сессии на странице входа (R7-sec, S2). Скрипт
// загрузки уводит на /login?m=session-expired, когда XHR прозрачно прошёл 303
// на форму входа: без объяснения пользователь видит логин вместо страницы
// приложения и не знает, что заливка не состоялась. Задача F18.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginShowsSessionExpiredNotice(t *testing.T) {
	e := newEnv(t)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/login?m=session-expired", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Your session has expired") {
		t.Errorf("нет объяснения на /login?m=session-expired: %s", rec.Body.String())
	}
	// Список сообщений закрытый: свободный текст из URL на странице входа —
	// готовый инструмент фишинга.
	other := httptest.NewRecorder()
	e.mux.ServeHTTP(other, httptest.NewRequest("GET", "/login?m=Your+account+is+compromised", nil))
	if strings.Contains(other.Body.String(), "compromised") {
		t.Error("страница входа показала произвольный текст из ?m=")
	}
}
