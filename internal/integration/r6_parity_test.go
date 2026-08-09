package integration

// Согласованность прав между интерфейсами: операция, доступная и через API, и
// через UI, обязана давать одной и той же роли один и тот же вердикт.
// F11 поймала одно расхождение (закрепление latest требовало PermVersion в API
// и PermApp в UI) — этот тест не даёт появиться следующему.

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"apprepo/internal/auth"
)

// opPair — одна операция в двух интерфейсах. perm — право, которое операция
// обязана требовать по матрице волны 6; ответ ожидается либо отказом (403),
// либо любым другим статусом («пропущено дальше по хендлеру»).
//
// Запросы нарочно адресуют несуществующие или уже занятые сущности: роль с
// правом получает 404/409, роль без права — 403, и ни один прогон не меняет
// состояние, поэтому порядок подтестов не важен.
type opPair struct {
	name string
	perm auth.Permission
	api  func(e *env, cr cred) (int, string)
	ui   func(e *env, c *http.Client) (int, string)
}

const parityApp = "parity"

var parityOps = []opPair{
	{
		name: "создать приложение",
		perm: auth.PermApp,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "POST", "/api/apps",
				strings.NewReader(`{"name":"`+parityApp+`"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/apps", url.Values{"name": {parityApp}})
		},
	},
	{
		name: "переименовать приложение",
		perm: auth.PermApp,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "PATCH", "/api/apps/nosuchapp",
				strings.NewReader(`{"name":"other"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/apps/nosuchapp/edit",
				url.Values{"name": {"other"}, "description": {""}})
		},
	},
	{
		name: "удалить приложение",
		perm: auth.PermApp,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "DELETE", "/api/apps/nosuchapp", nil, nil)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/apps/nosuchapp/delete",
				url.Values{"confirm": {"nosuchapp"}})
		},
	},
	{
		name: "залить версию",
		perm: auth.PermVersion,
		api: func(e *env, cr cred) (int, string) {
			// ?filename= и ?platform= обязательны (T23, T25): без них роль с
			// правом упёрлась бы в 400 и не дошла до дубля, ради которого
			// адресована занятая версия.
			return e.statusAs(cr, "PUT", "/api/apps/"+parityApp+"/versions/1.0.0?filename="+parityApp+"-1.0.0&platform="+testPlatform,
				strings.NewReader("dup"), nil)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uploadStatus(c, parityApp, "1.0.0", []byte("dup"))
		},
	},
	{
		name: "удалить версию",
		perm: auth.PermVersion,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "DELETE", "/api/apps/"+parityApp+"/versions/9.9.9", nil, nil)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/apps/"+parityApp+"/versions/9.9.9/delete", nil)
		},
	},
	{
		// Расхождение, найденное F11: API просил PermVersion, UI — PermApp.
		name: "закрепить latest",
		perm: auth.PermVersion,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "POST", "/api/apps/"+parityApp+"/latest",
				strings.NewReader(`{"version":"9.9.9"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/apps/"+parityApp+"/latest",
				url.Values{"version": {"9.9.9"}})
		},
	},
	{
		// Волна 8: простановка платформы — операция над версией, право у неё
		// то же, что у заливки и удаления (R8-test).
		name: "проставить платформу версии",
		perm: auth.PermVersion,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "PATCH", "/api/apps/"+parityApp+"/versions/9.9.9",
				strings.NewReader(`{"platform":"linux/amd64"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/apps/"+parityApp+"/versions/9.9.9/platform",
				url.Values{"platform_os": {"linux"}, "platform_arch": {"amd64"}})
		},
	},
	{
		name: "список учёток",
		perm: auth.PermUserAdmin,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "GET", "/api/users", nil, nil)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiStatus(c, "/users")
		},
	},
	{
		name: "создать учётку",
		perm: auth.PermUserAdmin,
		api: func(e *env, cr cred) (int, string) {
			// Пустое имя: роль с правом упирается в валидацию (400), без — 403.
			return e.statusAs(cr, "POST", "/api/users",
				strings.NewReader(`{"username":"","password":"valid-password","role":"developer"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/users",
				url.Values{"username": {""}, "password": {"valid-password"}, "role": {"developer"}})
		},
	},
	{
		name: "сменить роль учётки",
		perm: auth.PermUserAdmin,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "PATCH", "/api/users/nosuchuser",
				strings.NewReader(`{"role":"developer"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/users/999999/role", url.Values{"role": {"developer"}})
		},
	},
	{
		name: "заблокировать учётку",
		perm: auth.PermUserAdmin,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "PATCH", "/api/users/nosuchuser",
				strings.NewReader(`{"disabled":true}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/users/999999/disabled", url.Values{"disabled": {"true"}})
		},
	},
	{
		name: "сбросить чужой пароль",
		perm: auth.PermUserAdmin,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "POST", "/api/users/nosuchuser/password",
				strings.NewReader(`{"password":"valid-password"}`), jsonHdr)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/users/999999/password", url.Values{"password": {"valid-password"}})
		},
	},
	{
		name: "удалить учётку",
		perm: auth.PermUserAdmin,
		api: func(e *env, cr cred) (int, string) {
			return e.statusAs(cr, "DELETE", "/api/users/nosuchuser", nil, nil)
		},
		ui: func(e *env, c *http.Client) (int, string) {
			return e.uiPostStatus(c, "/users/999999/delete",
				url.Values{"confirm": {"nosuchuser"}})
		},
	},
}

// uploadStatus posts a multipart upload through the UI and returns status/body.
func (e *env) uploadStatus(c *http.Client, appName, version string, content []byte) (int, string) {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range [][2]string{{"csrf_token", e.csrfOf(c)}, {"version", version}, {"sha256", ""}, {"platform_os", testPlatform}} {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			e.t.Fatalf("WriteField %s: %v", f[0], err)
		}
	}
	fw, err := mw.CreateFormFile("file", appName+"-bin")
	if err != nil {
		e.t.Fatalf("CreateFormFile: %v", err)
	}
	fw.Write(content)
	mw.Close()
	req, err := http.NewRequest("POST", e.srv.URL+"/apps/"+appName+"/versions", &buf)
	if err != nil {
		e.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("POST upload: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, readBody(e.t, resp)
}

// TestPermissionParityAPIvsUI: для каждой пары «одна операция — два
// интерфейса» роль получает одинаковый вердикт в API и в UI, и этот вердикт
// совпадает с матрицей прав. deployer из сверки исключён осознанно: у роли нет
// PermUI вовсе, её отказ в интерфейсе — не расхождение, а смысл роли; она
// проверяется отдельным подтестом.
func TestPermissionParityAPIvsUI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	// Сущности, на которые ссылаются операции: приложение уже создано, версия
	// 1.0.0 уже залита — роль с правом упрётся в 409, а не создаст ничего.
	e.createApp(parityApp)
	e.mustPutVersion(parityApp, "1.0.0", "", []byte("seed"), "")

	for _, role := range auth.AllRoles() {
		if !role.Can(auth.PermUI) {
			continue
		}
		cr := e.mkUser("parity-"+string(role), "pw-"+string(role), string(role))
		c := e.mustLoginAs(cr)
		t.Run(string(role), func(t *testing.T) {
			for _, op := range parityOps {
				t.Run(op.name, func(t *testing.T) {
					apiCode, apiBody := op.api(e, cr)
					uiCode, uiBody := op.ui(e, c)
					apiDenied := deniedAPI(t, apiCode, apiBody)
					uiDenied := deniedUI(t, uiCode, uiBody)

					if apiDenied != uiDenied {
						t.Errorf("расхождение API и UI для роли %s: API %s (%d), UI %s (%d)",
							role, verdict(apiDenied), apiCode, verdict(uiDenied), uiCode)
					}
					if want := !role.Can(op.perm); apiDenied != want {
						t.Errorf("API: вердикт %s, по матрице должен быть %s (роль %s, право %v)",
							verdict(apiDenied), verdict(want), role, op.perm)
					}
				})
			}
		})
	}

	// deployer: машинная учётка. Вход в UI проходит (креды верные), но любая
	// страница отвечает отказом по роли, а API читает.
	t.Run("deployer", func(t *testing.T) {
		cr := e.mkUser("parity-deployer", "pw-deployer", string(auth.RoleDeployer))
		c := e.mustLoginAs(cr)
		for _, path := range []string{"/", "/apps/" + parityApp, "/users"} {
			code, body := e.uiStatus(c, path)
			if !deniedUI(t, code, body) {
				t.Errorf("GET %s для deployer: status = %d, want 403 (нет PermUI)", path, code)
			}
			if !strings.Contains(body, "the web interface is not available") {
				t.Errorf("страница отказа не объясняет deployer'у, что делать; body: %s", body)
			}
		}
		// Читать и качать он обязан.
		e.wantStatusAs(cr, "GET", "/api/apps", nil, http.StatusOK, "PermRead")
		e.wantStatusAs(cr, "GET", "/download/"+parityApp+"/1.0.0", nil, http.StatusOK, "PermRead")
		// А менять — нет.
		code, body := e.statusAs(cr, "POST", "/api/apps", strings.NewReader(`{"name":"x"}`), jsonHdr)
		if !deniedAPI(t, code, body) {
			t.Errorf("POST /api/apps для deployer: status = %d, want 403", code)
		}
		// Свой пароль он меняет через API — единственный доступный ему путь.
		e.wantStatusAs(cr, "POST", "/api/me/password",
			strings.NewReader(`{"current_password":"pw-deployer","new_password":"pw-deployer-2"}`),
			http.StatusNoContent, "смена своего пароля доступна любой роли")
	})
}

func verdict(denied bool) string {
	if denied {
		return "403"
	}
	return "пропущено"
}

// TestSelfServiceAvailableToEveryRole: /api/me и /api/me/password не требуют
// права вовсе — иначе deployer, которого не пускают в UI, не узнал бы себя и
// не сменил бы пароль ниоткуда.
func TestSelfServiceAvailableToEveryRole(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	for _, role := range auth.AllRoles() {
		role := role
		t.Run(string(role), func(t *testing.T) {
			cr := e.mkUser("self-"+string(role), "pw-"+string(role), string(role))
			code, body := e.statusAs(cr, "GET", "/api/me", nil, nil)
			if code != http.StatusOK {
				t.Fatalf("GET /api/me: status = %d, want 200; body: %s", code, body)
			}
			if !strings.Contains(body, `"role":"`+string(role)+`"`) {
				t.Errorf("/api/me показывает не ту роль: %s, want %s", body, role)
			}
			e.wantStatusAs(cr, "POST", "/api/me/password",
				strings.NewReader(`{"current_password":"pw-`+string(role)+`","new_password":"changed-pass"}`),
				http.StatusNoContent, "смена своего пароля")
			// Старый пароль больше не работает, новый работает.
			e.wantStatusAs(cr, "GET", "/api/me", nil, http.StatusUnauthorized, "старый пароль погашен")
			e.wantStatusAs(cred{cr.user, "changed-pass"}, "GET", "/api/me", nil,
				http.StatusOK, "новый пароль работает")
		})
	}
}

// TestUnknownRoleFailsClosed: роль, которой нет в матрице (осталась от чужой
// правки БД, будущего отката версии, ручного UPDATE), не должна давать ничего.
// Проверка на собранном приложении: в auth матрица «падает закрыто», важно,
// что этот принцип доживает до HTTP.
func TestUnknownRoleFailsClosed(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("closed")
	e.mustPutVersion("closed", "1.0.0", "", []byte("x"), "")
	cr := e.mkUser("weird", "weird-pass", string(auth.RoleDeveloper))
	if err := e.st.SetUserRole(e.userID("weird"), "superuser"); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}

	for _, path := range []string{
		"/api/apps", "/api/apps/closed", "/api/users", "/download/closed/1.0.0",
	} {
		code, body := e.statusAs(cr, "GET", path, nil, nil)
		if !deniedAPI(t, code, body) {
			t.Errorf("GET %s с неизвестной ролью: status = %d, want 403", path, code)
		}
	}
	// В интерфейс тоже не пускает, хотя вход по паролю проходит.
	c := e.mustLoginAs(cr)
	if code, body := e.uiStatus(c, "/"); !deniedUI(t, code, body) {
		t.Errorf("GET / с неизвестной ролью: status = %d, want 403", code)
	}
	// Своя учётка остаётся доступной — иначе такой пользователь не сменит
	// пароль и его нельзя будет разобрать без CLI.
	e.wantStatusAs(cr, "GET", "/api/me", nil, http.StatusOK, "/api/me без права")
}

// TestUsernameHandlingConsistency: одно и то же имя, введённое в API и в UI,
// обязано давать одну и ту же учётку, а всякая созданная учётка обязана быть
// работоспособной. Контракт сформулирован «либо на входе отказ, либо результат
// пригоден» — исправление вольно выбрать нормализацию или валидацию.
func TestUsernameHandlingConsistency(t *testing.T) {
	t.Run("api_и_ui_одинаково_нормализуют_имя", func(t *testing.T) {
		e := newEnv(t, defaultMaxUpload)
		// Разные имена в двух интерфейсах — чтобы второе создание не упиралось
		// в дубль первого; сравнивается сам факт нормализации, а не имя.
		const apiRaw, uiRaw = " pad-api ", " pad-ui "
		// Пароль — validPass (см. r6_helpers_test.go): подтест сравнивает имена
		// только после успешного создания, поэтому фикстура обязана быть годной
		// по политике, иначе оба интерфейса ответят 400 и тест выйдет ниже по
		// раннему return, ничего не сравнив.
		code, body := e.statusAs(adminCred, "POST", "/api/users",
			strings.NewReader(`{"username":"`+apiRaw+`","password":"`+validPass+`","role":"developer"}`), jsonHdr)
		apiOK := code == http.StatusCreated
		if !apiOK && code != http.StatusBadRequest {
			t.Fatalf("POST /api/users %q: status = %d; body: %s", apiRaw, code, body)
		}
		c := e.mustLoginAs(adminCred)
		uiCode, uiBody := e.uiPostStatus(c, "/users",
			url.Values{"username": {uiRaw}, "password": {validPass}, "role": {"developer"}})
		uiOK := uiCode == http.StatusSeeOther
		if !uiOK && uiCode != http.StatusBadRequest {
			t.Fatalf("POST /users %q: status = %d; body: %s", uiRaw, uiCode, uiBody)
		}
		if apiOK != uiOK {
			t.Fatalf("одно и то же по смыслу имя принято по-разному: API %d, UI %d", code, uiCode)
		}
		if !apiOK {
			return // оба отвергли — тоже согласованное поведение
		}
		users, err := e.st.ListUsers()
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		stored := map[string]string{} // маркер -> как легло в БД
		for _, u := range users {
			for _, marker := range []string{"pad-api", "pad-ui"} {
				if strings.Contains(u.Username, marker) {
					stored[marker] = u.Username
				}
			}
		}
		apiTrimmed := stored["pad-api"] == strings.TrimSpace(apiRaw)
		uiTrimmed := stored["pad-ui"] == strings.TrimSpace(uiRaw)
		if apiTrimmed != uiTrimmed {
			t.Errorf("API и UI нормализуют имя по-разному: API сохранил %q (обрезал: %v),"+
				" UI сохранил %q (обрезал: %v) — admin, повторив ту же операцию в другом"+
				" интерфейсе, заведёт вторую учётку с визуально тем же именем",
				stored["pad-api"], apiTrimmed, stored["pad-ui"], uiTrimmed)
		}
	})

	t.Run("созданная_учётка_умеет_войти", func(t *testing.T) {
		e := newEnv(t, defaultMaxUpload)
		// Двоеточие в имени: HTTP Basic кодирует "user:pass", поэтому такое имя
		// делает учётку неаутентифицируемой. Для deployer'а, у которого нет
		// другого входа кроме API, это учётка, непригодная с рождения.
		const name = "ci:bot"
		code, body := e.statusAs(adminCred, "POST", "/api/users",
			strings.NewReader(`{"username":"`+name+`","password":"`+validPass+`","role":"deployer"}`), jsonHdr)
		switch code {
		case http.StatusBadRequest:
			return // имя отвергнуто на входе — тоже корректный контракт
		case http.StatusCreated:
		default:
			t.Fatalf("POST /api/users %q: status = %d; body: %s", name, code, body)
		}
		me, meBody := e.statusAs(cred{name, validPass}, "GET", "/api/me", nil, nil)
		if me != http.StatusOK {
			t.Errorf("учётка %q создана (201), но войти по Basic нельзя: status = %d, body: %s;"+
				" имя пользователя нигде не валидируется", name, me, meBody)
		}
	})
}
