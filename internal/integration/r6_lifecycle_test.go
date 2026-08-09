package integration

// Полный жизненный цикл учётки сквозь HTTP и немедленное гашение сессий.
// Проверяется собранное приложение: то, что admin сделал через API или UI,
// обязано менять доступ владельца учётки в тот же момент — и по сессии в
// интерфейсе, и по Basic-кредам.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"apprepo/internal/auth"
)

// wantSessionDead asserts that the UI client's session no longer works: любой
// защищённый маршрут отправляет на /login, а не отдаёт страницу.
func (e *env) wantSessionDead(c *http.Client, why string) {
	e.t.Helper()
	code, body := e.uiStatus(c, "/")
	if code != http.StatusSeeOther {
		e.t.Errorf("сессия жива после %s: GET / status = %d, want 303 на /login; body: %s",
			why, code, body)
	}
}

// wantSessionAlive asserts the UI client still has a working session.
func (e *env) wantSessionAlive(c *http.Client, why string) {
	e.t.Helper()
	if code, body := e.uiStatus(c, "/"); code != http.StatusOK {
		e.t.Errorf("сессия не работает %s: GET / status = %d, want 200; body: %s", why, code, body)
	}
}

// wantSessionRecognized asserts the session is still accepted by the server:
// страница может ответить отказом по роли (403), но не редиректом на /login.
func (e *env) wantSessionRecognized(c *http.Client, why string) {
	e.t.Helper()
	if code, body := e.uiStatus(c, "/"); code == http.StatusSeeOther {
		e.t.Errorf("сессия не признана %s: GET / status = 303 на /login; body: %s", why, body)
	}
}

// wantBasicDead asserts the credentials no longer authenticate at all.
func (e *env) wantBasicDead(cr cred, why string) {
	e.t.Helper()
	code, body := e.statusAs(cr, "GET", "/api/me", nil, nil)
	if code != http.StatusUnauthorized {
		e.t.Errorf("Basic-креды живы после %s: GET /api/me status = %d, want 401; body: %s",
			why, code, body)
	}
}

// TestAccountLifecycleOverHTTP: admin заводит developer'а → тот работает →
// разжалован в deployer → заблокирован → разблокирован → удалён. На каждом
// шаге сверяются оба канала: Basic для API и сессия для UI.
func TestAccountLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("life")

	dev := e.mkUser("dev", "dev-pass", string(auth.RoleDeveloper))

	t.Run("developer_заливает_версию_но_не_трогает_приложение", func(t *testing.T) {
		e.wantStatusAs(dev, "PUT", "/api/apps/life/versions/1.0.0?filename=life-1.0.0&platform="+testPlatform,
			strings.NewReader("v1"), http.StatusCreated, "PermVersion есть")
		code, body := e.statusAs(dev, "DELETE", "/api/apps/life", nil, nil)
		if !deniedAPI(t, code, body) {
			t.Errorf("удаление приложения developer'ом: status = %d, want 403", code)
		}
		// Приложение на месте — отказ не был «403 после дела».
		e.wantStatusAs(adminCred, "GET", "/api/apps/life", nil, http.StatusOK,
			"приложение уцелело")
	})

	devUI := e.mustLoginAs(dev)
	e.wantSessionAlive(devUI, "у developer'а")

	t.Run("разжалование_в_deployer_закрывает_UI_сразу", func(t *testing.T) {
		code, body := e.patchUser(adminCred, "dev", `{"role":"deployer"}`)
		if code != http.StatusOK {
			t.Fatalf("PATCH роли: status = %d, want 200; body: %s", code, body)
		}
		// Сессия остаётся действительной (пароль не менялся), но роль уже
		// другая: интерфейс отвечает отказом по роли, а не пускает.
		uiCode, uiBody := e.uiStatus(devUI, "/")
		if !deniedUI(t, uiCode, uiBody) {
			t.Errorf("после разжалования UI отдал status = %d, want 403", uiCode)
		}
		// Новый вход тоже не открывает интерфейс.
		fresh := e.mustLoginAs(dev)
		if code, body := e.uiStatus(fresh, "/"); !deniedUI(t, code, body) {
			t.Errorf("свежая сессия deployer'а пустила в UI: status = %d", code)
		}
		// Basic продолжает работать на чтение и теряет право заливки.
		e.wantStatusAs(dev, "GET", "/api/apps", nil, http.StatusOK, "deployer читает")
		code, body = e.statusAs(dev, "PUT", "/api/apps/life/versions/2.0.0?filename=life-2.0.0&platform="+testPlatform,
			strings.NewReader("v2"), nil)
		if !deniedAPI(t, code, body) {
			t.Errorf("заливка deployer'ом: status = %d, want 403; body: %s", code, body)
		}
		if code, _ := e.statusAs(adminCred, "GET", "/api/apps/life/versions/2.0.0", nil, nil); code != http.StatusNotFound {
			t.Errorf("версия 2.0.0 всё-таки создана: status = %d, want 404", code)
		}
	})

	t.Run("блокировка_гасит_и_Basic_и_сессию", func(t *testing.T) {
		blocked := e.mustLoginAs(dev) // живая сессия до блокировки
		// У deployer'а нет PermUI, поэтому «жива» здесь значит «признана»:
		// сервер отвечает отказом по роли, а не отправляет на /login.
		e.wantSessionRecognized(blocked, "у deployer'а до блокировки")
		code, body := e.patchUser(adminCred, "dev", `{"disabled":true}`)
		if code != http.StatusOK {
			t.Fatalf("PATCH disabled: status = %d, want 200; body: %s", code, body)
		}
		e.wantBasicDead(dev, "блокировки")
		e.wantSessionDead(blocked, "блокировки")
		// Войти заново тоже нельзя, и причина неотличима от неверного пароля.
		if _, code := e.loginAs(dev, "/"); code != http.StatusUnauthorized {
			t.Errorf("вход заблокированного: status = %d, want 401", code)
		}
	})

	t.Run("разблокировка_возвращает_доступ", func(t *testing.T) {
		code, body := e.patchUser(adminCred, "dev", `{"disabled":false}`)
		if code != http.StatusOK {
			t.Fatalf("PATCH disabled=false: status = %d, want 200; body: %s", code, body)
		}
		e.wantStatusAs(dev, "GET", "/api/me", nil, http.StatusOK, "разблокирован")
		if _, code := e.loginAs(dev, "/"); code != http.StatusSeeOther {
			t.Errorf("вход после разблокировки: status = %d, want 303", code)
		}
	})

	t.Run("удаление_даёт_401", func(t *testing.T) {
		gone := e.mustLoginAs(dev)
		code, body := e.statusAs(adminCred, "DELETE", "/api/users/dev", nil, nil)
		if code != http.StatusNoContent {
			t.Fatalf("DELETE /api/users/dev: status = %d, want 204; body: %s", code, body)
		}
		e.wantBasicDead(dev, "удаления")
		e.wantSessionDead(gone, "удаления")
		// Строка сессии ушла вместе с учёткой (FK ON DELETE CASCADE).
		if _, err := e.st.GetUser("dev"); err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if u, _ := e.st.GetUser("dev"); u != nil {
			t.Errorf("учётка не удалена из БД")
		}
	})
}

// TestSessionInvalidation: каждая из четырёх операций обязана немедленно
// погасить и активную сессию в UI, и работающие Basic-креды.
func TestSessionInvalidation(t *testing.T) {
	tests := []struct {
		name string
		// do выполняет операцию; возвращает креды, которые ДОЛЖНЫ работать
		// после неё (пустые — значит никакие).
		do func(t *testing.T, e *env, victim cred) cred
	}{
		{
			name: "смена_своего_пароля_через_API",
			do: func(t *testing.T, e *env, victim cred) cred {
				e.wantStatusAs(victim, "POST", "/api/me/password",
					strings.NewReader(`{"current_password":"`+victim.pass+`","new_password":"brand-new"}`),
					http.StatusNoContent, "смена своего пароля")
				return cred{victim.user, "brand-new"}
			},
		},
		{
			name: "смена_своего_пароля_через_UI",
			do: func(t *testing.T, e *env, victim cred) cred {
				c := e.mustLoginAs(victim)
				code, body := e.uiPostStatus(c, "/password", url.Values{
					"current": {victim.pass}, "password": {"brand-new"}, "confirm": {"brand-new"},
				})
				if code != http.StatusSeeOther {
					t.Fatalf("POST /password: status = %d, want 303; body: %s", code, body)
				}
				return cred{victim.user, "brand-new"}
			},
		},
		{
			name: "сброс_пароля_админом",
			do: func(t *testing.T, e *env, victim cred) cred {
				e.wantStatusAs(adminCred, "POST", "/api/users/"+victim.user+"/password",
					strings.NewReader(`{"password":"reset-by-admin"}`),
					http.StatusNoContent, "сброс пароля админом")
				return cred{victim.user, "reset-by-admin"}
			},
		},
		{
			name: "сброс_пароля_админом_через_UI",
			do: func(t *testing.T, e *env, victim cred) cred {
				c := e.mustLoginAs(adminCred)
				code, body := e.uiPostStatus(c, "/users/"+strconv.FormatInt(e.userID(victim.user), 10)+"/password",
					url.Values{"password": {"reset-by-admin"}})
				if code != http.StatusSeeOther {
					t.Fatalf("POST сброса пароля в UI: status = %d, want 303; body: %s", code, body)
				}
				return cred{victim.user, "reset-by-admin"}
			},
		},
		{
			name: "блокировка",
			do: func(t *testing.T, e *env, victim cred) cred {
				if code, body := e.patchUser(adminCred, victim.user, `{"disabled":true}`); code != http.StatusOK {
					t.Fatalf("PATCH disabled: status = %d; body: %s", code, body)
				}
				return cred{}
			},
		},
		{
			name: "удаление",
			do: func(t *testing.T, e *env, victim cred) cred {
				code, body := e.statusAs(adminCred, "DELETE", "/api/users/"+victim.user, nil, nil)
				if code != http.StatusNoContent {
					t.Fatalf("DELETE учётки: status = %d, want 204; body: %s", code, body)
				}
				return cred{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, defaultMaxUpload)
			victim := e.mkUser("victim", "victim-pass", string(auth.RoleMaintainer))
			// Две живые сессии: гасить надо все, а не только текущую.
			s1 := e.mustLoginAs(victim)
			s2 := e.mustLoginAs(victim)
			e.wantSessionAlive(s1, "до операции")
			e.wantSessionAlive(s2, "до операции")

			stillValid := tt.do(t, e, victim)

			e.wantSessionDead(s1, tt.name)
			e.wantSessionDead(s2, tt.name)
			e.wantBasicDead(victim, tt.name)
			if stillValid.user != "" {
				e.wantStatusAs(stillValid, "GET", "/api/me", nil, http.StatusOK,
					"новые креды обязаны работать")
			}
		})
	}
}

// TestUserManagementValidationOverHTTP: отказы, которые видит живой человек, —
// пустой пароль, неверный текущий пароль, несуществующая роль. Проверяется,
// что операция не выполняется и оба интерфейса объясняют причину.
func TestUserManagementValidationOverHTTP(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	victim := e.mkUser("val", "val-pass", string(auth.RoleDeveloper))
	c := e.mustLoginAs(adminCred)
	victimID := strconv.FormatInt(e.userID(victim.user), 10)

	t.Run("api_неверный_текущий_пароль_не_меняет_свой", func(t *testing.T) {
		code, body := e.statusAs(victim, "POST", "/api/me/password",
			strings.NewReader(`{"current_password":"wrong","new_password":"hacked"}`), jsonHdr)
		if code != http.StatusForbidden || !strings.Contains(body, "current password is incorrect") {
			t.Errorf("status = %d, body = %s; want 403 и объяснение", code, body)
		}
		e.wantStatusAs(victim, "GET", "/api/me", nil, http.StatusOK, "старый пароль работает")
		e.wantStatusAs(cred{victim.user, "hacked"}, "GET", "/api/me", nil,
			http.StatusUnauthorized, "новый пароль не установлен")
	})

	t.Run("api_несуществующая_роль_отвергается", func(t *testing.T) {
		code, body := e.patchUser(adminCred, victim.user, `{"role":"root"}`)
		if code != http.StatusBadRequest || !strings.Contains(body, "unknown role") {
			t.Errorf("status = %d, body = %s; want 400 unknown role", code, body)
		}
		if got := e.mustStoreUser(victim.user).Role; got != string(auth.RoleDeveloper) {
			t.Errorf("роль изменилась на %q несмотря на отказ", got)
		}
	})

	t.Run("api_пустой_пароль_при_сбросе_отвергается", func(t *testing.T) {
		code, body := e.statusAs(adminCred, "POST", "/api/users/"+victim.user+"/password",
			strings.NewReader(`{"password":""}`), jsonHdr)
		if code != http.StatusBadRequest || !strings.Contains(body, "must not be empty") {
			t.Errorf("status = %d, body = %s; want 400", code, body)
		}
		e.wantStatusAs(victim, "GET", "/api/me", nil, http.StatusOK, "пароль не сброшен")
	})

	t.Run("api_битый_json_отвергается_без_изменений", func(t *testing.T) {
		for _, tc := range []struct{ method, path string }{
			{"POST", "/api/users"},
			{"PATCH", "/api/users/" + victim.user},
			{"POST", "/api/users/" + victim.user + "/password"},
			{"POST", "/api/me/password"},
		} {
			code, body := e.statusAs(adminCred, tc.method, tc.path,
				strings.NewReader("{not json"), jsonHdr)
			if code != http.StatusBadRequest || !strings.Contains(body, "invalid JSON body") {
				t.Errorf("%s %s с битым телом: status = %d, body = %s; want 400",
					tc.method, tc.path, code, body)
			}
		}
		if got := e.mustStoreUser(victim.user).Role; got != string(auth.RoleDeveloper) {
			t.Errorf("роль изменилась на %q после битого тела", got)
		}
		e.wantStatusAs(victim, "GET", "/api/me", nil, http.StatusOK, "пароль не тронут")
	})

	t.Run("ui_пустой_пароль_при_создании_учётки", func(t *testing.T) {
		code, body := e.uiPostStatus(c, "/users",
			url.Values{"username": {"nopass"}, "password": {""}, "role": {"developer"}})
		if code != http.StatusBadRequest || !strings.Contains(body, "password must not be empty") {
			t.Errorf("status = %d; страница не объясняет отказ; body: %s", code, body)
		}
		if u, _ := e.st.GetUser("nopass"); u != nil {
			t.Error("учётка создана без пароля")
		}
	})

	t.Run("ui_несуществующая_роль_отвергается", func(t *testing.T) {
		code, body := e.uiPostStatus(c, "/users/"+victimID+"/role", url.Values{"role": {"root"}})
		if code != http.StatusBadRequest || !strings.Contains(body, "unknown role") {
			t.Errorf("status = %d; body: %s; want 400 unknown role", code, body)
		}
	})

	t.Run("ui_пустой_пароль_при_сбросе", func(t *testing.T) {
		code, body := e.uiPostStatus(c, "/users/"+victimID+"/password", url.Values{"password": {""}})
		if code != http.StatusBadRequest || !strings.Contains(body, "must not be empty") {
			t.Errorf("status = %d; body: %s; want 400", code, body)
		}
	})

	t.Run("ui_смена_своего_пароля_проверяет_текущий_и_повтор", func(t *testing.T) {
		vc := e.mustLoginAs(victim)
		for _, tc := range []struct {
			name string
			form url.Values
			want int
			msg  string
		}{
			{"неверный текущий", url.Values{"current": {"nope"},
				"password": {"new-password"}, "confirm": {"new-password"}},
				http.StatusUnauthorized, "current password is incorrect"},
			{"пустой новый", url.Values{"current": {"val-pass"}, "password": {""}, "confirm": {""}},
				http.StatusBadRequest, "must not be empty"},
			// Пароли валидны по политике и различны: проверяется именно
			// несовпадение повтора, а не длина (порядок проверок в
			// web.changeOwnPassword — длина раньше повтора).
			{"короткий новый", url.Values{"current": {"val-pass"},
				"password": {"short"}, "confirm": {"short"}},
				http.StatusBadRequest, "at least 8 bytes"},
			{"повтор не совпал", url.Values{"current": {"val-pass"},
				"password": {"password-a"}, "confirm": {"password-b"}},
				http.StatusBadRequest, "do not match"},
		} {
			code, body := e.uiPostStatus(vc, "/password", tc.form)
			if code != tc.want || !strings.Contains(body, tc.msg) {
				t.Errorf("%s: status = %d, want %d; сообщение %q не найдено", tc.name, code, tc.want, tc.msg)
			}
		}
		// Ни одна из неудач не погасила сессию и не сменила пароль.
		e.wantSessionAlive(vc, "после неудачных попыток")
		e.wantStatusAs(victim, "GET", "/api/me", nil, http.StatusOK, "пароль не менялся")
	})

	t.Run("ui_сброс_себе_выбрасывает_на_login", func(t *testing.T) {
		// Отдельная ветка в web.resetUserPassword: сброс собственного пароля
		// гасит и текущую сессию, поэтому редирект идёт на /login, а не /users.
		self := e.mustLoginAs(adminCred)
		id := strconv.FormatInt(e.userID(testUser), 10)
		resp := e.uiPost(self, "/users/"+id+"/password", url.Values{
			"csrf_token": {e.csrfOf(self)}, "password": {"admin-new-pass"},
		})
		loc := resp.Header.Get("Location")
		code := resp.StatusCode
		resp.Body.Close()
		if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/login") {
			t.Errorf("сброс себе: status = %d, Location = %q; want 303 на /login", code, loc)
		}
		e.wantSessionDead(self, "сброса своего пароля")
		e.wantBasicDead(adminCred, "сброса своего пароля")
		e.wantStatusAs(cred{testUser, "admin-new-pass"}, "GET", "/api/me", nil,
			http.StatusOK, "новый пароль админа")
	})
}
