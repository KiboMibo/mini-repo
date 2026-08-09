package web

// F19 (R7-qa, находка 3): классификация неудачной загрузки в UI. Клиентская
// ошибка — 4xx, сбой сервера — 500 с записью в лог; те же классы, что и в
// api.uploadErr. Прежний default отвечал 400 «upload failed» на что угодно, и
// поломка диска приезжала в мониторинг ошибкой пользователя.
//
// Тест внутренний (package web), а не сквозной: обе default-ветки достижимы
// только настоящим сбоем ФС, который из чёрного ящика воспроизводится лишь
// правами доступа — а тесты гоняются в том числе от root, где их нет.
// Классификация от этого не перестаёт быть контрактом: проверяется прямым
// вызовом с синтетической ошибкой.

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/store"
)

func newUploadErrTestHandlers(t *testing.T) (*handlers, *store.App) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "apprepo.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	app, err := st.CreateApp("myapp", "")
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	h := &handlers{
		st:   st,
		auth: &auth.Auth{Store: st},
		cfg:  config.Config{MaxUploadBytes: 1024},
		tpl: map[string]*template.Template{
			"app": template.Must(template.ParseFS(tplFS, "templates/layout.html", "templates/app.html")),
		},
	}
	return h, app
}

func TestUploadErrorClassification(t *testing.T) {
	h, app := newUploadErrTestHandlers(t)

	cases := []struct {
		name string
		call func(w http.ResponseWriter, r *http.Request, err error)
		err  error
		want int
		why  string
	}{
		{
			name: "publish_failure_is_server_error",
			call: func(w http.ResponseWriter, r *http.Request, err error) { h.uploadError(w, r, app, err) },
			err:  errors.New("link /data/.tmp/upload-1 /data/myapp/1.0.0/x: no space left on device"),
			want: http.StatusInternalServerError,
			why:  "сбой ФС при публикации — сбой сервера, как и в api.uploadErr",
		},
		{
			name: "malformed_body_is_client_error",
			call: func(w http.ResponseWriter, r *http.Request, err error) { h.multipartError(w, r, app, err) },
			err:  errors.New(`malformed MIME header line: Content-Disposition: form-data; name="file"`),
			want: http.StatusBadRequest,
			why:  "неразбираемое тело — негодный запрос, не сбой",
		},
		{
			name: "too_large_keeps_its_own_code",
			call: func(w http.ResponseWriter, r *http.Request, err error) { h.multipartError(w, r, app, err) },
			err:  fmt.Errorf("read body: %w", &http.MaxBytesError{Limit: 1024}),
			want: http.StatusRequestEntityTooLarge,
			why:  "превышение лимита не должно утонуть в общем 400",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/apps/myapp/versions", nil)
			tc.call(w, r, tc.err)
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d (%s)", w.Code, tc.want, tc.why)
			}
			// Внутренние подробности (пути ФС, SQLite) клиенту не уходят ни в
			// одном из классов — инвариант о генеричных 500 в силе.
			if body := w.Body.String(); tc.want >= 500 {
				if len(body) > 0 && body != "internal server error\n" {
					t.Errorf("500 отдал не генеричный текст: %q", body)
				}
			}
		})
	}
}
