package integration

// Утечки: ни один ответ (JSON API и HTML интерфейса) не содержит bcrypt-хеша
// пароля, и ни пароль, ни хеш не попадают в журнал сервера.

import (
	"bytes"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"apprepo/internal/auth"
)

// captureLog redirects the standard logger into a buffer for the duration of
// the test. Пакет log глобален, поэтому подтесты, использующие захват, не
// помечаются t.Parallel.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags, prefix := log.Flags(), log.Prefix()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr) // дефолт пакета log — вернуть как было
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	})
	return &buf
}

// TestNoPasswordHashInResponses: хеш пароля не появляется ни в одном ответе,
// который может увидеть пользователь.
func TestNoPasswordHashInResponses(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("leaky")
	e.mustPutVersion("leaky", "1.0.0", "", []byte("bytes"), "")
	victim := e.mkUser("leak-victim", "leak-pass", string(auth.RoleDeveloper))
	hash := e.mustStoreUser(victim.user).PasswordHash
	adminHash := e.mustStoreUser(testUser).PasswordHash
	if hash == "" || !strings.HasPrefix(hash, "$2") {
		t.Fatalf("подготовка: хеш выглядит не как bcrypt: %q", hash)
	}

	check := func(what, body string) {
		t.Helper()
		for name, secret := range map[string]string{
			"хеш чужого пароля": hash,
			"хеш своего пароля": adminHash,
		} {
			if strings.Contains(body, secret) {
				t.Errorf("%s: в ответе %s", what, name)
			}
		}
		// Заодно — любой bcrypt-хеш, даже не наш.
		if strings.Contains(body, "$2a$") || strings.Contains(body, "$2b$") {
			t.Errorf("%s: в ответе строка, похожая на bcrypt-хеш; body: %s", what, body)
		}
	}

	t.Run("api", func(t *testing.T) {
		for _, path := range []string{
			"/api/users", "/api/me", "/api/apps", "/api/apps/leaky",
			"/api/apps/leaky/versions", "/api/apps/leaky/versions/1.0.0",
			"/api/apps/leaky/latest",
		} {
			_, body := e.statusAs(adminCred, "GET", path, nil, nil)
			check("GET "+path, body)
		}
		// Ответ на создание учётки — тоже объект пользователя.
		_, body := e.statusAs(adminCred, "POST", "/api/users",
			strings.NewReader(`{"username":"leak-2","password":"leak-2-password","role":"deployer"}`), jsonHdr)
		check("POST /api/users", body)
		// И ответ на смену роли.
		_, body = e.patchUser(adminCred, "leak-2", `{"role":"developer"}`)
		check("PATCH /api/users/leak-2", body)
	})

	t.Run("html", func(t *testing.T) {
		c := e.mustLoginAs(adminCred)
		for _, path := range []string{"/", "/apps/leaky", "/users", "/login"} {
			_, body := e.uiStatus(c, path)
			check("GET "+path, body)
		}
		// Страница со списком учёток после неудачной операции (форма с ошибкой)
		// рендерит тех же пользователей — проверяем и её.
		id := strconv.FormatInt(e.userID(testUser), 10)
		_, body := e.uiPostStatus(c, "/users/"+id+"/role", url.Values{"role": {"developer"}})
		check("POST /users/{id}/role (409)", body)
		// Страница отказа по роли — её видит deployer.
		dep := e.mkUser("leak-deployer", "dep-pass", string(auth.RoleDeployer))
		dc := e.mustLoginAs(dep)
		_, body = e.uiStatus(dc, "/")
		check("страница отказа для deployer", body)
	})
}

// TestPasswordsNotLogged: журнал сервера не содержит ни пароля, ни хеша, ни
// токена сессии — только имена пользователей (инвариант из CLAUDE.md).
func TestPasswordsNotLogged(t *testing.T) {
	buf := captureLog(t)
	e := newEnv(t, defaultMaxUpload)

	const (
		created  = "created-secret-pw"
		reset    = "reset-secret-pw"
		selfNew  = "self-secret-pw"
		uiCreate = "ui-secret-pw"
	)
	u := e.mkUser("logged", created, string(auth.RoleDeveloper))

	e.wantStatusAs(adminCred, "POST", "/api/users/logged/password",
		strings.NewReader(`{"password":"`+reset+`"}`), 204, "сброс пароля")
	e.wantStatusAs(cred{u.user, reset}, "POST", "/api/me/password",
		strings.NewReader(`{"current_password":"`+reset+`","new_password":"`+selfNew+`"}`),
		204, "смена своего пароля")

	c := e.mustLoginAs(adminCred)
	if code, body := e.uiPostStatus(c, "/users", url.Values{
		"username": {"logged-ui"}, "password": {uiCreate}, "role": {"developer"},
	}); code != 303 {
		t.Fatalf("создание учётки в UI: status = %d, want 303; body: %s", code, body)
	}

	// Токен живой сессии админа — тоже секрет.
	token := e.sessionOf(c)

	logged := buf.String()
	for name, secret := range map[string]string{
		"пароль при создании учётки (API)": created,
		"пароль при сбросе админом":        reset,
		"новый пароль при смене своего":    selfNew,
		"пароль при создании учётки (UI)":  uiCreate,
		"хеш пароля":   e.mustStoreUser("logged").PasswordHash,
		"токен сессии": token,
	} {
		if secret != "" && strings.Contains(logged, secret) {
			t.Errorf("в журнале оказался %s", name)
		}
	}
	// Осмысленность проверки: журнал не пустой и имена в нём есть.
	if !strings.Contains(logged, `"logged"`) {
		t.Errorf("журнал не содержит имени пользователя — проверка утечки бессмысленна; log: %s", logged)
	}
}
