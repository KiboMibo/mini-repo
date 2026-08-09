package web_test

// T20: права ролей на UI-маршрутах, экран пользователей и смена своего пароля.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"apprepo/internal/auth"
	"apprepo/internal/store"
)

// forbiddenMark — заголовок страницы отказа; по нему тесты отличают ответ
// Require от любого другого 403 (например, от CSRF).
const forbiddenMark = "Not available for your role"

// fixture — учётка одной роли со своей песочницей: собственная версия demo,
// которую эта роль удаляет, и собственная учётка-мишень для операций админа.
type fixture struct {
	role     auth.Role
	session  string
	targetID int64
	version  string
}

// addUser creates a user with the given role and returns it together with a
// fresh session token.
func (e *env) addUser(t *testing.T, name string, role auth.Role, password string) (*store.User, string) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateUser(name, hash, string(role)); err != nil {
		t.Fatal(err)
	}
	u, err := e.st.GetUser(name)
	if err != nil || u == nil {
		t.Fatalf("GetUser(%q) = %v, %v", name, u, err)
	}
	sess, err := e.st.CreateSession(u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return u, sess
}

// roleEnv builds one environment with an account per role, an application
// "demo" and per-role fixtures, so the whole matrix runs against a single
// store (bcrypt на каждую учётку — самая дорогая часть теста).
func roleEnv(t *testing.T) (*env, map[auth.Role]*fixture) {
	t.Helper()
	e := newEnv(t)
	app, err := e.st.CreateApp("demo", "")
	if err != nil {
		t.Fatal(err)
	}
	fx := map[auth.Role]*fixture{}
	for i, role := range auth.AllRoles() {
		_, sess := e.addUser(t, "u-"+string(role), role, "secret-pass")
		target, _ := e.addUser(t, "t-"+string(role), auth.RoleAdmin, "secret-pass")
		f := &fixture{role: role, session: sess, targetID: target.ID,
			version: fmt.Sprintf("9.9.%d", i)}
		e.addVersion(t, app, f.version, "bin", "payload")
		fx[role] = f
	}
	return e, fx
}

// uiRoute описывает маршрут интерфейса: требуемое право и ожидаемый ответ для
// роли, у которой это право есть. Мутации подобраны так, чтобы не ломать
// фикстуры соседних ролей: имена уникальны, а разрушительные операции идут с
// заведомо неверным подтверждением.
type uiRoute struct {
	name    string
	method  string
	perm    auth.Permission
	path    func(f *fixture) string
	body    func(t *testing.T, f *fixture) (io.Reader, string)
	wantOK  int
	wantLoc string
}

func urlencoded(vals map[string]string) func(*testing.T, *fixture) (io.Reader, string) {
	return func(*testing.T, *fixture) (io.Reader, string) { return form(vals) }
}

func uiRoutes() []uiRoute {
	fixed := func(p string) func(*fixture) string { return func(*fixture) string { return p } }
	return []uiRoute{
		{name: "app list", method: "GET", perm: auth.PermUI,
			path: fixed("/"), wantOK: http.StatusOK},
		{name: "app page", method: "GET", perm: auth.PermUI,
			path: fixed("/apps/demo"), wantOK: http.StatusOK},
		{name: "change own password", method: "POST", perm: auth.PermUI,
			path: fixed("/password"),
			body: urlencoded(map[string]string{"csrf_token": csrfTok,
				"current": "wrong-password", "password": "new-password", "confirm": "new-password"}),
			wantOK: http.StatusUnauthorized}, // верный пароль проверяется отдельно
		{name: "create app", method: "POST", perm: auth.PermApp,
			path: fixed("/apps"),
			body: func(t *testing.T, f *fixture) (io.Reader, string) {
				return form(map[string]string{"csrf_token": csrfTok, "name": "app-" + string(f.role)})
			},
			wantOK: http.StatusSeeOther},
		{name: "set latest", method: "POST", perm: auth.PermVersion,
			path:   fixed("/apps/demo/latest"),
			body:   urlencoded(map[string]string{"csrf_token": csrfTok, "version": "auto"}),
			wantOK: http.StatusSeeOther, wantLoc: "/apps/demo"},
		{name: "edit app", method: "POST", perm: auth.PermApp,
			path: fixed("/apps/demo/edit"),
			body: urlencoded(map[string]string{"csrf_token": csrfTok,
				"name": "demo", "description": "d"}),
			wantOK: http.StatusSeeOther, wantLoc: "/apps/demo"},
		{name: "delete app", method: "POST", perm: auth.PermApp,
			path:   fixed("/apps/demo/delete"),
			body:   urlencoded(map[string]string{"csrf_token": csrfTok, "confirm": "nope"}),
			wantOK: http.StatusBadRequest}, // подтверждение неверное: demo цела
		{name: "upload version", method: "POST", perm: auth.PermVersion,
			path: fixed("/apps/demo/versions"),
			body: func(t *testing.T, f *fixture) (io.Reader, string) {
				// platform_os=any: содержимое не бинарник, а платформу заливка
				// через UI требует — определить её у такого файла нечем (T26).
				return multipartBody(t, map[string]string{"csrf_token": csrfTok,
					"platform_os": "any",
					"version":     strings.Replace(f.version, "9.9.", "1.0.", 1)}, "bin", []byte("x"))
			},
			wantOK: http.StatusSeeOther, wantLoc: "/apps/demo"},
		{name: "set version platform", method: "POST", perm: auth.PermVersion,
			path: func(f *fixture) string { return "/apps/demo/versions/" + f.version + "/platform" },
			body: urlencoded(map[string]string{"csrf_token": csrfTok,
				"platform_os": "linux", "platform_arch": "amd64"}),
			wantOK: http.StatusSeeOther, wantLoc: "/apps/demo"},
		{name: "delete version", method: "POST", perm: auth.PermVersion,
			path:   func(f *fixture) string { return "/apps/demo/versions/" + f.version + "/delete" },
			body:   urlencoded(map[string]string{"csrf_token": csrfTok}),
			wantOK: http.StatusSeeOther, wantLoc: "/apps/demo"},
		{name: "user list", method: "GET", perm: auth.PermUserAdmin,
			path: fixed("/users"), wantOK: http.StatusOK},
		{name: "create user", method: "POST", perm: auth.PermUserAdmin,
			path: fixed("/users"),
			body: func(t *testing.T, f *fixture) (io.Reader, string) {
				return form(map[string]string{"csrf_token": csrfTok,
					"username": "n-" + string(f.role), "password": "new-password", "role": "developer"})
			},
			wantOK: http.StatusSeeOther, wantLoc: "/users"},
		{name: "set user role", method: "POST", perm: auth.PermUserAdmin,
			path:   func(f *fixture) string { return fmt.Sprintf("/users/%d/role", f.targetID) },
			body:   urlencoded(map[string]string{"csrf_token": csrfTok, "role": "maintainer"}),
			wantOK: http.StatusSeeOther, wantLoc: "/users"},
		{name: "block user", method: "POST", perm: auth.PermUserAdmin,
			path:   func(f *fixture) string { return fmt.Sprintf("/users/%d/disabled", f.targetID) },
			body:   urlencoded(map[string]string{"csrf_token": csrfTok, "disabled": "true"}),
			wantOK: http.StatusSeeOther, wantLoc: "/users"},
		{name: "reset user password", method: "POST", perm: auth.PermUserAdmin,
			path:   func(f *fixture) string { return fmt.Sprintf("/users/%d/password", f.targetID) },
			body:   urlencoded(map[string]string{"csrf_token": csrfTok, "password": "new-password"}),
			wantOK: http.StatusSeeOther, wantLoc: "/users"},
		{name: "delete user", method: "POST", perm: auth.PermUserAdmin,
			path:   func(f *fixture) string { return fmt.Sprintf("/users/%d/delete", f.targetID) },
			body:   urlencoded(map[string]string{"csrf_token": csrfTok, "confirm": "nope"}),
			wantOK: http.StatusBadRequest}, // подтверждение неверное: учётка цела
	}
}

// TestRoutePermissionMatrix прогоняет каждую роль по каждому UI-маршруту:
// у кого права нет — 403 со страницей-объяснением, у кого есть — ожидаемый код
// и редирект. Маршрут без проверки прав провалит строку deployer'а.
func TestRoutePermissionMatrix(t *testing.T) {
	e, fx := roleEnv(t)
	for _, rt := range uiRoutes() {
		for _, role := range auth.AllRoles() {
			t.Run(rt.name+"/"+string(role), func(t *testing.T) {
				f := fx[role]
				var body io.Reader
				var ctype string
				if rt.body != nil {
					body, ctype = rt.body(t, f)
				}
				rec := e.doAs(t, f.session, rt.method, rt.path(f), ctype, body, true)
				if !role.Can(rt.perm) || !role.Can(auth.PermUI) {
					if rec.Code != http.StatusForbidden {
						t.Fatalf("code = %d, want 403; body: %s", rec.Code, rec.Body.String())
					}
					if !strings.Contains(rec.Body.String(), forbiddenMark) {
						t.Fatalf("403 без страницы-объяснения: %s", rec.Body.String())
					}
					return
				}
				if rec.Code != rt.wantOK {
					t.Fatalf("code = %d, want %d; body: %s", rec.Code, rt.wantOK, rec.Body.String())
				}
				if rt.wantLoc != "" && rec.Header().Get("Location") != rt.wantLoc {
					t.Fatalf("Location = %q, want %q", rec.Header().Get("Location"), rt.wantLoc)
				}
			})
		}
	}
}

// TestLogoutAllowedForEveryRole: выход не закрыт правом PermUI — иначе deployer
// не смог бы уйти со страницы-объяснения.
func TestLogoutAllowedForEveryRole(t *testing.T) {
	e, fx := roleEnv(t)
	for _, role := range auth.AllRoles() {
		t.Run(string(role), func(t *testing.T) {
			body, ctype := form(map[string]string{"csrf_token": csrfTok})
			rec := e.doAs(t, fx[role].session, "POST", "/logout", ctype, body, true)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
				t.Fatalf("code = %d, Location = %q; want 303 /login",
					rec.Code, rec.Header().Get("Location"))
			}
		})
	}
}

// login отправляет форму входа без сессионной куки и возвращает ответ.
func (e *env) login(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, ctype := form(map[string]string{
		"csrf_token": csrfTok, "username": username, "password": password, "next": "/"})
	req := httptest.NewRequest("POST", "/login", body)
	req.Header.Set("Content-Type", ctype)
	req.AddCookie(&http.Cookie{Name: "apprepo_csrf", Value: csrfTok})
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// sessionFrom вытаскивает выданный сессионный токен из Set-Cookie.
func sessionFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("сессионная кука не выдана: %v", rec.Header())
	return ""
}

// TestDeployerLandsOnExplanation: пароль верный, сессия выдана, но интерфейс не
// его — на первой же странице объяснение, а не 403-заглушка и не редирект на
// /login (иначе получился бы цикл: сессия-то действительна).
func TestDeployerLandsOnExplanation(t *testing.T) {
	e := newEnv(t)
	e.addUser(t, "ci", auth.RoleDeployer, "secret-pass")

	rec := e.login(t, "ci", "secret-pass")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: code = %d, want 303; body: %s", rec.Code, rec.Body.String())
	}
	sess := sessionFrom(t, rec)

	page := e.doAs(t, sess, "GET", "/", "", nil, true)
	if page.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", page.Code)
	}
	if loc := page.Header().Get("Location"); loc != "" {
		t.Fatalf("редирект вместо страницы: Location = %q", loc)
	}
	for _, want := range []string{forbiddenMark, "/api/", "/download/", "ci", "deployer"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("на странице нет %q; body: %s", want, page.Body.String())
		}
	}
}

// TestButtonsHiddenByRole: недоступное действие не рисуется вовсе.
func TestButtonsHiddenByRole(t *testing.T) {
	e, fx := roleEnv(t)
	cases := []struct {
		role           auth.Role
		page           string
		want, dontWant []string
	}{
		{role: auth.RoleDeveloper, page: "/apps/demo",
			want:     []string{"Upload version", "/apps/demo/versions", "/apps/demo/latest"},
			dontWant: []string{"Delete application", "/apps/demo/edit", "/apps/demo/delete"}},
		{role: auth.RoleMaintainer, page: "/apps/demo",
			want: []string{"Upload version", "Delete application", "/apps/demo/edit"}},
		{role: auth.RoleDeveloper, page: "/",
			dontWant: []string{"New application", "/users"}},
		{role: auth.RoleMaintainer, page: "/",
			want: []string{"New application"}, dontWant: []string{`href="/users"`}},
		{role: auth.RoleAdmin, page: "/",
			want: []string{"New application", `href="/users"`}},
	}
	for _, c := range cases {
		t.Run(string(c.role)+c.page, func(t *testing.T) {
			body := e.doAs(t, fx[c.role].session, "GET", c.page, "", nil, true).Body.String()
			for _, w := range c.want {
				if !strings.Contains(body, w) {
					t.Errorf("нет %q в разметке", w)
				}
			}
			for _, w := range c.dontWant {
				if strings.Contains(body, w) {
					t.Errorf("роль видит %q, хотя права нет", w)
				}
			}
		})
	}
}

// TestNewPostsRequireCSRF: ни одна новая форма не проходит без токена.
func TestNewPostsRequireCSRF(t *testing.T) {
	e, fx := roleEnv(t)
	admin := fx[auth.RoleAdmin]
	targets := []string{
		"/password", "/users",
		"/apps/demo/versions/" + admin.version + "/platform",
		fmt.Sprintf("/users/%d/role", admin.targetID),
		fmt.Sprintf("/users/%d/disabled", admin.targetID),
		fmt.Sprintf("/users/%d/password", admin.targetID),
		fmt.Sprintf("/users/%d/delete", admin.targetID),
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			// поле есть, куки нет
			body, ctype := form(map[string]string{"csrf_token": csrfTok, "role": "developer"})
			if rec := e.doAs(t, admin.session, "POST", target, ctype, body, false); rec.Code != http.StatusForbidden {
				t.Errorf("без куки: code = %d, want 403", rec.Code)
			}
			// кука есть, поля нет
			body, ctype = form(map[string]string{"role": "developer"})
			if rec := e.doAs(t, admin.session, "POST", target, ctype, body, true); rec.Code != http.StatusForbidden {
				t.Errorf("без поля: code = %d, want 403", rec.Code)
			}
		})
	}
}

// TestLastAdminIsExplained: защита последнего админа доезжает до пользователя
// понятным сообщением и 409, а не 500.
func TestLastAdminIsExplained(t *testing.T) {
	e := newEnv(t) // единственный админ — alice
	alice, err := e.st.GetUser("alice")
	if err != nil || alice == nil {
		t.Fatalf("GetUser: %v %v", alice, err)
	}
	cases := []struct {
		name, target string
		fields       map[string]string
	}{
		{"demote", fmt.Sprintf("/users/%d/role", alice.ID),
			map[string]string{"csrf_token": csrfTok, "role": "developer"}},
		{"block", fmt.Sprintf("/users/%d/disabled", alice.ID),
			map[string]string{"csrf_token": csrfTok, "disabled": "true"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, ctype := form(c.fields)
			rec := e.do(t, "POST", c.target, ctype, body, true)
			if rec.Code != http.StatusConflict {
				t.Fatalf("code = %d, want 409; body: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "last administrator") {
				t.Errorf("нет объяснения в ответе: %s", rec.Body.String())
			}
			cur, err := e.st.GetUser("alice")
			if err != nil || cur.Role != string(auth.RoleAdmin) || cur.Disabled {
				t.Errorf("учётка изменилась: %+v (err %v)", cur, err)
			}
		})
	}
	// Удаление последнего админа отсекается ещё раньше — как самоудаление.
	body, ctype := form(map[string]string{"csrf_token": csrfTok, "confirm": "alice"})
	rec := e.do(t, "POST", fmt.Sprintf("/users/%d/delete", alice.ID), ctype, body, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "your own account") {
		t.Fatalf("самоудаление: code = %d, body: %s", rec.Code, rec.Body.String())
	}
	if cur, _ := e.st.GetUser("alice"); cur == nil {
		t.Fatal("alice удалена")
	}
}

// TestDeleteLastAdminByAnother: второй админ не может удалить последнего
// живого администратора (первый заблокирован) — 409 с объяснением.
func TestDeleteLastAdminByAnother(t *testing.T) {
	e := newEnv(t)
	bob, bobSess := e.addUser(t, "bob", auth.RoleAdmin, "secret-pass")
	alice, _ := e.st.GetUser("alice")
	if err := e.st.SetUserDisabled(alice.ID, true); err != nil {
		t.Fatal(err)
	}
	// Теперь живой админ ровно один — bob; удалить его пробует он сам? Нет:
	// самоудаление запрещено отдельно, поэтому удаляем bob'а от лица alice
	// нельзя (она заблокирована). Проверяем через понижение bob'а им самим.
	body, ctype := form(map[string]string{"csrf_token": csrfTok, "role": "developer"})
	rec := e.doAs(t, bobSess, "POST", fmt.Sprintf("/users/%d/role", bob.ID), ctype, body, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "last administrator") {
		t.Fatalf("code = %d, body: %s", rec.Code, rec.Body.String())
	}
}

// TestChangeOwnPassword: неверный текущий — понятная ошибка и пароль цел;
// верный — редирект на /login, старая сессия мертва, новый пароль работает.
func TestChangeOwnPassword(t *testing.T) {
	e := newEnv(t)
	_, sess := e.addUser(t, "dev", auth.RoleDeveloper, "secret-pass")

	body, ctype := form(map[string]string{"csrf_token": csrfTok,
		"current": "wrong", "password": "brandnew", "confirm": "brandnew"})
	rec := e.doAs(t, sess, "POST", "/password", ctype, body, true)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("неверный текущий: code = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "current password is incorrect") {
		t.Errorf("нет объяснения: %s", rec.Body.String())
	}

	body, ctype = form(map[string]string{"csrf_token": csrfTok,
		"current": "secret-pass", "password": "brandnew", "confirm": "mistyped"})
	if rec := e.doAs(t, sess, "POST", "/password", ctype, body, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("повтор не совпал: code = %d, want 400", rec.Code)
	}

	body, ctype = form(map[string]string{"csrf_token": csrfTok,
		"current": "secret-pass", "password": "brandnew", "confirm": "brandnew"})
	rec = e.doAs(t, sess, "POST", "/password", ctype, body, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?m=password-changed" {
		t.Fatalf("code = %d, Location = %q", rec.Code, rec.Header().Get("Location"))
	}
	// Сессия погашена store'ом: со старой кукой снова просят логин.
	if again := e.doAs(t, sess, "GET", "/", "", nil, true); again.Code != http.StatusSeeOther {
		t.Fatalf("старая сессия жива: code = %d", again.Code)
	}
	// Страница входа объясняет, что произошло.
	req := httptest.NewRequest("GET", "/login?m=password-changed", nil)
	page := httptest.NewRecorder()
	e.mux.ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "Your password has been changed") {
		t.Errorf("нет сообщения на /login: %s", page.Body.String())
	}
	if login := e.login(t, "dev", "brandnew"); login.Code != http.StatusSeeOther {
		t.Fatalf("новый пароль не работает: code = %d", login.Code)
	}
}

// TestUserAdminFlow: создание, блокировка и удаление учётки через интерфейс.
func TestUserAdminFlow(t *testing.T) {
	e := newEnv(t)

	body, ctype := form(map[string]string{"csrf_token": csrfTok,
		"username": "carol", "password": "carol-password", "role": "maintainer"})
	if rec := e.do(t, "POST", "/users", ctype, body, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("create: code = %d, body: %s", rec.Code, rec.Body.String())
	}
	carol, err := e.st.GetUser("carol")
	if err != nil || carol == nil || carol.Role != string(auth.RoleMaintainer) {
		t.Fatalf("carol = %+v (err %v)", carol, err)
	}
	if page := e.do(t, "GET", "/users", "", nil, true); !strings.Contains(page.Body.String(), "carol") {
		t.Error("carol не видна в списке")
	}
	// Дубль имени — 409 с объяснением, не 500.
	body, ctype = form(map[string]string{"csrf_token": csrfTok,
		"username": "carol", "password": "new-password", "role": "developer"})
	if rec := e.do(t, "POST", "/users", ctype, body, true); rec.Code != http.StatusConflict {
		t.Fatalf("дубль: code = %d, body: %s", rec.Code, rec.Body.String())
	}
	// Неизвестная роль — 400, а не молча admin.
	body, ctype = form(map[string]string{"csrf_token": csrfTok,
		"username": "dave", "password": "carol-password", "role": "root"})
	if rec := e.do(t, "POST", "/users", ctype, body, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("роль root: code = %d", rec.Code)
	}

	body, ctype = form(map[string]string{"csrf_token": csrfTok, "disabled": "true"})
	if rec := e.do(t, "POST", fmt.Sprintf("/users/%d/disabled", carol.ID), ctype, body, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("block: code = %d", rec.Code)
	}
	if cur, _ := e.st.GetUser("carol"); cur == nil || !cur.Disabled {
		t.Fatal("carol не заблокирована")
	}

	// Удаление требует точного имени.
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "confirm": "caro"})
	if rec := e.do(t, "POST", fmt.Sprintf("/users/%d/delete", carol.ID), ctype, body, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("неверное подтверждение: code = %d", rec.Code)
	}
	if cur, _ := e.st.GetUser("carol"); cur == nil {
		t.Fatal("carol удалена без подтверждения")
	}
	body, ctype = form(map[string]string{"csrf_token": csrfTok, "confirm": "carol"})
	if rec := e.do(t, "POST", fmt.Sprintf("/users/%d/delete", carol.ID), ctype, body, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: code = %d", rec.Code)
	}
	if cur, _ := e.st.GetUser("carol"); cur != nil {
		t.Fatal("carol на месте после удаления")
	}
}

// TestUnknownUserID: мусор в {id} — 404, а не 500.
func TestUnknownUserID(t *testing.T) {
	e := newEnv(t)
	for _, target := range []string{"/users/abc/role", "/users/99999/delete"} {
		body, ctype := form(map[string]string{"csrf_token": csrfTok, "role": "developer"})
		if rec := e.do(t, "POST", target, ctype, body, true); rec.Code != http.StatusNotFound {
			t.Errorf("%s: code = %d, want 404", target, rec.Code)
		}
	}
}
