package api_test

// T19: права на маршрутах API и управление пользователями.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"apprepo/internal/auth"
)

// doAs is do(...) for an arbitrary account: матрица прав проверяется чужими
// учётками, а не admin'ом из newMux.
func doAs(t *testing.T, mux *http.ServeMux, user, pass, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetBasicAuth(user, pass)
	if body != "" {
		req.Header.Set("Content-Type", "application/json") // рубеж notJSON, как в do
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// mustCreateUser заводит учётку от имени admin'а (testUser) через API.
func mustCreateUser(t *testing.T, mux *http.ServeMux, name, pass, role string) {
	t.Helper()
	w := do(t, mux, "POST", "/api/users",
		`{"username":"`+name+`","password":"`+pass+`","role":"`+role+`"}`, nil)
	wantStatus(t, w, http.StatusCreated)
}

// routeCase — маршрут, требуемое право и код успешного ответа для роли,
// которая правом обладает; роль без права обязана получить 403.
type routeCase struct {
	method, path, body string
	perm               auth.Permission
	ok                 int
}

// roleRoutes перечисляет ВСЕ маршруты /api/ и /download/ в порядке, в котором
// их можно выполнить подряд одной учёткой (чтение → своя учётка → users →
// версии → приложения). Уникальные имена берутся из роли, чтобы прогон одной
// роли не мешал другой.
//
// PermRead у /api/me и /api/me/password означает «доступно всем ролям»: сами
// маршруты навешаны без Require вовсе, а PermRead есть у каждой роли.
func roleRoutes(role string) []routeCase {
	return []routeCase{
		{"GET", "/api/apps", "", auth.PermRead, http.StatusOK},
		{"GET", "/api/apps/myapp", "", auth.PermRead, http.StatusOK},
		{"GET", "/api/apps/myapp/versions", "", auth.PermRead, http.StatusOK},
		{"GET", "/api/apps/myapp/versions/1.0.0", "", auth.PermRead, http.StatusOK},
		{"GET", "/api/apps/myapp/latest", "", auth.PermRead, http.StatusOK},
		{"GET", "/download/myapp/1.0.0", "", auth.PermRead, http.StatusOK},
		{"GET", "/api/unknown-route", "", auth.PermRead, http.StatusNotFound},

		{"GET", "/api/me", "", auth.PermRead, http.StatusOK},
		{"POST", "/api/me/password",
			`{"current_password":"role-password","new_password":"role-password"}`,
			auth.PermRead, http.StatusNoContent},

		{"GET", "/api/users", "", auth.PermUserAdmin, http.StatusOK},
		{"POST", "/api/users",
			`{"username":"made-by-` + role + `","password":"made-password","role":"deployer"}`,
			auth.PermUserAdmin, http.StatusCreated},
		{"PATCH", "/api/users/target", `{"role":"maintainer","disabled":false}`,
			auth.PermUserAdmin, http.StatusOK},
		{"POST", "/api/users/target/password", `{"password":"reset-password"}`,
			auth.PermUserAdmin, http.StatusNoContent},
		{"DELETE", "/api/users/target", "", auth.PermUserAdmin, http.StatusNoContent},

		{"POST", "/api/apps/myapp/latest", `{"version":"1.0.0"}`,
			auth.PermVersion, http.StatusOK},
		{"PUT", "/api/apps/myapp/versions/2.0.0?filename=myapp-2.0.0&platform=any", "binary",
			auth.PermVersion, http.StatusCreated},
		// Простановка платформы руками — то же право, что у заливки (T25).
		{"PATCH", "/api/apps/myapp/versions/2.0.0", `{"platform":"linux/amd64"}`,
			auth.PermVersion, http.StatusOK},
		{"DELETE", "/api/apps/myapp/versions/2.0.0", "", auth.PermVersion, http.StatusNoContent},

		{"POST", "/api/apps", `{"name":"app-` + role + `"}`, auth.PermApp, http.StatusCreated},
		{"PATCH", "/api/apps/myapp", `{"description":"changed"}`, auth.PermApp, http.StatusOK},
		{"DELETE", "/api/apps/myapp", "", auth.PermApp, http.StatusNoContent},
	}
}

// TestRoleMatrix — каждая роль против каждого маршрута: успех или 403 ровно по
// матрице прав. В частности deployer: качает и меняет свой пароль, но не может
// ни залить версию, ни тронуть /api/users.
func TestRoleMatrix(t *testing.T) {
	const pw = "role-password"
	for _, role := range auth.AllRoles() {
		t.Run(string(role), func(t *testing.T) {
			mux := newMux(t)
			// Фикстуру готовит admin из newMux.
			createApp(t, mux, "myapp")
			wantStatus(t, putVersion(t, mux, "myapp", "1.0.0", "bin", nil), http.StatusCreated)
			mustCreateUser(t, mux, string(role), pw, string(role))
			mustCreateUser(t, mux, "target", "target-password", "developer")

			for _, c := range roleRoutes(string(role)) {
				want := http.StatusForbidden
				if auth.Role(role).Can(c.perm) {
					want = c.ok
				}
				w := doAs(t, mux, string(role), pw, c.method, c.path, c.body)
				if w.Code != want {
					t.Errorf("%s %s: status = %d, want %d; body: %s",
						c.method, c.path, w.Code, want, w.Body.String())
					continue
				}
				if want == http.StatusForbidden {
					if m := decode(t, w); m["error"] != "forbidden" {
						t.Errorf("%s %s: 403 body = %s, want forbidden JSON",
							c.method, c.path, w.Body.String())
					}
				}
			}
		})
	}
}

// TestUsersListShape: список отдаёт нужные поля и ни при каких условиях —
// хеш пароля.
func TestUsersListShape(t *testing.T) {
	mux := newMux(t)
	mustCreateUser(t, mux, "bob", "bob-password", "deployer")

	w := do(t, mux, "GET", "/api/users", "", nil)
	wantStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if strings.Contains(body, "$2") || strings.Contains(strings.ToLower(body), "password") {
		t.Fatalf("список пользователей содержит пароль/хеш: %s", body)
	}
	var us []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &us); err != nil || len(us) != 2 {
		t.Fatalf("users list: %s (err %v)", body, err)
	}
	if us[0]["username"] != testUser || us[0]["role"] != "admin" || us[0]["disabled"] != false {
		t.Fatalf("первый пользователь: %v", us[0])
	}
	if us[1]["username"] != "bob" || us[1]["role"] != "deployer" {
		t.Fatalf("второй пользователь: %v", us[1])
	}
	if created, _ := us[1]["created_at"].(string); !strings.HasSuffix(created, "Z") {
		t.Fatalf("created_at = %v, want RFC 3339 UTC", us[1]["created_at"])
	}
}

// TestUserValidation — коды ошибок на кривых входных данных.
func TestUserValidation(t *testing.T) {
	mux := newMux(t)
	mustCreateUser(t, mux, "bob", "bob-password", "developer")

	wantErr(t, do(t, mux, "POST", "/api/users",
		`{"username":"bob","password":"valid-password","role":"admin"}`, nil),
		http.StatusConflict, "already_exists")
	wantErr(t, do(t, mux, "POST", "/api/users",
		`{"username":"eve","password":"valid-password","role":"root"}`, nil),
		http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "POST", "/api/users",
		`{"username":"eve","password":"","role":"admin"}`, nil),
		http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "POST", "/api/users",
		`{"username":"","password":"valid-password","role":"admin"}`, nil),
		http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "POST", "/api/users", `{`, nil),
		http.StatusBadRequest, "validation")

	wantErr(t, do(t, mux, "PATCH", "/api/users/bob", `{"role":"root"}`, nil),
		http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "POST", "/api/users/bob/password", `{"password":""}`, nil),
		http.StatusBadRequest, "validation")

	// Несуществующая учётка — 404 на всех трёх маршрутах.
	wantErr(t, do(t, mux, "PATCH", "/api/users/nobody", `{"role":"admin"}`, nil),
		http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "POST", "/api/users/nobody/password", `{"password":"valid-password"}`, nil),
		http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "DELETE", "/api/users/nobody", "", nil),
		http.StatusNotFound, "not_found")

	// Пустое тело PATCH ничего не меняет — как у PATCH приложения.
	w := do(t, mux, "PATCH", "/api/users/bob", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["role"] != "developer" || m["disabled"] != false {
		t.Fatalf("пустой PATCH изменил учётку: %s", w.Body.String())
	}
}

// TestLastAdminAndSelfDelete: последнего админа нельзя разжаловать, заблокировать
// или удалить, а себя — удалить в принципе.
func TestLastAdminAndSelfDelete(t *testing.T) {
	mux := newMux(t)

	wantErr(t, do(t, mux, "PATCH", "/api/users/"+testUser, `{"role":"developer"}`, nil),
		http.StatusConflict, "last_admin")
	wantErr(t, do(t, mux, "PATCH", "/api/users/"+testUser, `{"disabled":true}`, nil),
		http.StatusConflict, "last_admin")
	// Себя удалить нельзя даже при наличии второго админа — проверка идёт до store.
	wantErr(t, do(t, mux, "DELETE", "/api/users/"+testUser, "", nil),
		http.StatusConflict, "self_delete")

	// Учётка цела: роль и доступ не изменились.
	w := do(t, mux, "GET", "/api/me", "", nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["username"] != testUser || m["role"] != "admin" {
		t.Fatalf("/api/me = %s", w.Body.String())
	}

	// Второй админ снимает защиту: теперь понижение проходит.
	mustCreateUser(t, mux, "bob", "bob-password", "admin")
	w = do(t, mux, "PATCH", "/api/users/"+testUser, `{"role":"developer"}`, nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["role"] != "developer" {
		t.Fatalf("роль после понижения = %v", m["role"])
	}
	// И права ушли вместе с ролью.
	wantStatus(t, do(t, mux, "GET", "/api/users", "", nil), http.StatusForbidden)
}

// TestDisabledUserCannotAuthenticate: блокировка через API закрывает Basic Auth.
func TestDisabledUserCannotAuthenticate(t *testing.T) {
	mux := newMux(t)
	mustCreateUser(t, mux, "bob", "bob-password", "developer")
	wantStatus(t, doAs(t, mux, "bob", "bob-password", "GET", "/api/apps", ""), http.StatusOK)

	w := do(t, mux, "PATCH", "/api/users/bob", `{"disabled":true}`, nil)
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["disabled"] != true {
		t.Fatalf("disabled = %v, want true", m["disabled"])
	}
	w = doAs(t, mux, "bob", "bob-password", "GET", "/api/apps", "")
	wantErr(t, w, http.StatusUnauthorized, "unauthorized")

	// Разблокировка возвращает доступ.
	wantStatus(t, do(t, mux, "PATCH", "/api/users/bob", `{"disabled":false}`, nil), http.StatusOK)
	wantStatus(t, doAs(t, mux, "bob", "bob-password", "GET", "/api/apps", ""), http.StatusOK)
}

// TestAdminResetPassword: сброс пароля админом реально меняет пароль.
func TestAdminResetPassword(t *testing.T) {
	mux := newMux(t)
	mustCreateUser(t, mux, "bob", "bob-password", "deployer")

	wantStatus(t, do(t, mux, "POST", "/api/users/bob/password", `{"password":"new-password"}`, nil),
		http.StatusNoContent)
	wantStatus(t, doAs(t, mux, "bob", "bob-password", "GET", "/api/apps", ""), http.StatusUnauthorized)
	wantStatus(t, doAs(t, mux, "bob", "new-password", "GET", "/api/apps", ""), http.StatusOK)
}

// TestChangeOwnPassword: смена своего пароля доступна deployer'у — учётке,
// которую в UI не пускают вовсе.
func TestChangeOwnPassword(t *testing.T) {
	mux := newMux(t)
	mustCreateUser(t, mux, "dep", "dep-password", "deployer")

	w := doAs(t, mux, "dep", "dep-password", "GET", "/api/me", "")
	wantStatus(t, w, http.StatusOK)
	if m := decode(t, w); m["username"] != "dep" || m["role"] != "deployer" {
		t.Fatalf("/api/me = %s", w.Body.String())
	}

	// Неверный текущий пароль — 403, пароль не меняется. Код отличается от
	// "forbidden" (нехватка права): вердикты разные и лечатся по-разному.
	w = doAs(t, mux, "dep", "dep-password", "POST", "/api/me/password",
		`{"current_password":"wrong-password","new_password":"new-password"}`)
	wantErr(t, w, http.StatusForbidden, "invalid_password")
	// Пустой новый — 400.
	w = doAs(t, mux, "dep", "dep-password", "POST", "/api/me/password",
		`{"current_password":"dep-password","new_password":""}`)
	wantErr(t, w, http.StatusBadRequest, "validation")
	// Старый пароль всё ещё рабочий.
	wantStatus(t, doAs(t, mux, "dep", "dep-password", "GET", "/api/apps", ""), http.StatusOK)

	w = doAs(t, mux, "dep", "dep-password", "POST", "/api/me/password",
		`{"current_password":"dep-password","new_password":"new-password"}`)
	wantStatus(t, w, http.StatusNoContent)
	wantStatus(t, doAs(t, mux, "dep", "dep-password", "GET", "/api/apps", ""), http.StatusUnauthorized)
	wantStatus(t, doAs(t, mux, "dep", "new-password", "GET", "/api/apps", ""), http.StatusOK)
}
