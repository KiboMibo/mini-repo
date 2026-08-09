package api_test

// Задача F14: рубеж Content-Type на /api/ — строгий белый список из одного
// application/json. Денилист F12 (text/plain + multipart/form-data) класс не
// закрывал: запрос вообще без заголовка проходил и создавал админа
// (S1 круга 2 ревью R6-sec).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// crossSiteCT — весь класс Content-Type, с которым кросс-сайтовый запрос уходит
// из браузера без preflight (значит, доступен атакующему), плюс неразбираемый
// мусор: заголовок, который не разобрался, рубеж обязан считать отказом, а не
// пропуском. Пустая строка — заголовка нет вовсе; так уходит
// navigator.sendBeacon с Blob, у которого пустой type.
var crossSiteCT = []string{
	"",
	"text/plain",
	"text/plain;charset=UTF-8",
	"multipart/form-data; boundary=x",
	"application/x-www-form-urlencoded",
	"garbage",
	"/",
	"text/plain;;;",
}

// doCT sends body with exactly the given Content-Type; ct == "" means no header
// at all. Мимо do(): тот проставляет application/json непустому телу, а здесь
// проверяется именно отсутствие и негодность заголовка.
func doCT(t *testing.T, mux *http.ServeMux, method, path, ct, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetBasicAuth(testUser, testPass)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// TestContentTypeStrictOnUserRoutes — критерий приёмки S1: два маршрута,
// которыми захватывают установку, отвечают 415 на весь класс кросс-сайтовых
// Content-Type и ничего при этом не меняют.
func TestContentTypeStrictOnUserRoutes(t *testing.T) {
	mux := newMux(t)

	// Тело — чистый валидный JSON: именно его доставляет fetch/sendBeacon,
	// в отличие от `поле=значение` настоящей HTML-формы.
	const createBody = `{"username":"evil","password":"pw1234567","role":"admin"}`
	const resetBody = `{"password":"hijacked1"}`

	for _, ct := range crossSiteCT {
		wantErr(t, doCT(t, mux, "POST", "/api/users", ct, createBody),
			http.StatusUnsupportedMediaType, "unsupported_media_type")
		wantErr(t, doCT(t, mux, "POST", "/api/users/"+testUser+"/password", ct, resetBody),
			http.StatusUnsupportedMediaType, "unsupported_media_type")
	}

	// Учётка не создана (пустой PATCH — самый дешёвый способ спросить о ней:
	// отдельного GET одной учётки в API нет).
	wantErr(t, do(t, mux, "PATCH", "/api/users/evil", "", nil), http.StatusNotFound, "not_found")
	if body := do(t, mux, "GET", "/api/users", "", nil).Body.String(); strings.Contains(body, "evil") {
		t.Fatalf("учётка evil создана кросс-сайтовым телом: %s", body)
	}
	// Пароль админа не заменён: старым паролем всё ещё пускает.
	wantStatus(t, do(t, mux, "GET", "/api/me", "", nil), http.StatusOK)

	// Разрешённое работает как раньше — в том числе с параметром charset и в
	// любом регистре: сравнивается разобранный media type, а не строка.
	for i, ct := range []string{"application/json", "application/json; charset=utf-8", "APPLICATION/JSON"} {
		name := "good" + string(rune('a'+i))
		wantStatus(t, doCT(t, mux, "POST", "/api/users", ct,
			`{"username":"`+name+`","password":"pw1234567","role":"developer"}`), http.StatusCreated)
		wantStatus(t, doCT(t, mux, "POST", "/api/users/"+name+"/password", ct,
			`{"password":"another-pw"}`), http.StatusNoContent)
	}
}

// TestContentTypeStrictOnAppRoutes: рубеж стоит в единственной точке разбора
// JSON, поэтому он же закрывает и маршруты приложений.
func TestContentTypeStrictOnAppRoutes(t *testing.T) {
	mux := newMux(t)
	for _, ct := range crossSiteCT {
		wantErr(t, doCT(t, mux, "POST", "/api/apps", ct, `{"name":"evilapp"}`),
			http.StatusUnsupportedMediaType, "unsupported_media_type")
	}
	wantErr(t, do(t, mux, "GET", "/api/apps/evilapp", "", nil), http.StatusNotFound, "not_found")
}

// TestEmptyBodyNeedsNoContentType: пустое тело — легальный «ничего не менять»,
// и Content-Type ему не нужен; доставить им всё равно нечего.
func TestEmptyBodyNeedsNoContentType(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	wantStatus(t, doCT(t, mux, "PATCH", "/api/apps/myapp", "", ""), http.StatusOK)
	wantStatus(t, doCT(t, mux, "PATCH", "/api/users/"+testUser, "", ""), http.StatusOK)
}
