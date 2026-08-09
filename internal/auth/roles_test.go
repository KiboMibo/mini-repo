package auth

// T18: матрица прав, ParseRole и middleware Require; отказ аутентификации
// заблокированному по обоим путям (сессия и Basic).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"apprepo/internal/store"
)

// TestRoleCan — вся матрица прав из постановки T18, 4 роли × 5 прав.
func TestRoleCan(t *testing.T) {
	perms := []struct {
		name string
		p    Permission
	}{
		{"read", PermRead},
		{"version", PermVersion},
		{"app", PermApp},
		{"useradmin", PermUserAdmin},
		{"ui", PermUI},
	}
	//                      read   version app    useradmin ui
	want := map[Role][5]bool{
		RoleDeployer:   {true, false, false, false, false},
		RoleDeveloper:  {true, true, false, false, true},
		RoleMaintainer: {true, true, true, false, true},
		RoleAdmin:      {true, true, true, true, true},
	}
	for _, r := range AllRoles() {
		row, ok := want[r]
		if !ok {
			t.Fatalf("role %q has no row in the expected matrix", r)
		}
		for i, pc := range perms {
			if got := r.Can(pc.p); got != row[i] {
				t.Errorf("%s.Can(%s) = %v, want %v", r, pc.name, got, row[i])
			}
		}
	}
	// Роль, не прошедшая ParseRole, не даёт ничего (fail closed).
	for _, pc := range perms {
		if Role("").Can(pc.p) || Role("root").Can(pc.p) {
			t.Errorf("unknown role granted %s", pc.name)
		}
	}
}

func TestAllRoles(t *testing.T) {
	got := AllRoles()
	want := []Role{RoleDeployer, RoleDeveloper, RoleMaintainer, RoleAdmin}
	if len(got) != len(want) {
		t.Fatalf("AllRoles() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllRoles() = %v, want %v (по возрастанию прав)", got, want)
		}
	}
	// Порядок объявлен как возрастание прав — проверяем это, а не только состав.
	for i := 1; i < len(got); i++ {
		for _, p := range []Permission{PermRead, PermVersion, PermApp, PermUserAdmin, PermUI} {
			if got[i-1].Can(p) && !got[i].Can(p) {
				t.Errorf("%s can %d but the more privileged %s cannot", got[i-1], p, got[i])
			}
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range AllRoles() {
		got, err := ParseRole(string(r))
		if err != nil || got != r {
			t.Errorf("ParseRole(%q) = %q, %v", r, got, err)
		}
	}
	for _, s := range []string{"", " ", "Admin", "ADMIN", "admin ", " admin", "administrator",
		"root", "deployer\n", "developer,maintainer", "*"} {
		if got, err := ParseRole(s); err == nil {
			t.Errorf("ParseRole(%q) = %q, want error", s, got)
		}
	}
}

// requireHandler — Require поверх контекста с пользователем роли role.
func requireHandler(a *Auth, p Permission, u *store.User) http.Handler {
	inner := a.Require(p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u != nil {
			r = withUser(r, u)
		}
		inner.ServeHTTP(w, r)
	})
}

func TestRequire(t *testing.T) {
	a := &Auth{}

	t.Run("allows and denies per matrix", func(t *testing.T) {
		for _, r := range AllRoles() {
			for _, p := range []Permission{PermRead, PermVersion, PermApp, PermUserAdmin, PermUI} {
				w := httptest.NewRecorder()
				requireHandler(a, p, &store.User{Username: "u", Role: string(r)}).
					ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
				want := 200
				if !r.Can(p) {
					want = http.StatusForbidden
				}
				if w.Code != want {
					t.Errorf("%s, perm %d: code = %d, want %d", r, p, w.Code, want)
				}
			}
		}
	})

	t.Run("403 body is the API error format", func(t *testing.T) {
		w := httptest.NewRecorder()
		requireHandler(a, PermUserAdmin, &store.User{Role: string(RoleDeveloper)}).
			ServeHTTP(w, httptest.NewRequest("GET", "/api/users", nil))
		if w.Code != 403 || !strings.Contains(w.Body.String(), `"error":"forbidden"`) {
			t.Errorf("code = %d, body = %q", w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
	})

	t.Run("no user in context is denied", func(t *testing.T) {
		w := httptest.NewRecorder()
		requireHandler(a, PermRead, nil).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 403 {
			t.Errorf("code = %d, want 403", w.Code)
		}
	})

	t.Run("Forbidden overrides the response", func(t *testing.T) {
		ui := &Auth{Forbidden: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "нет доступа", http.StatusForbidden)
		}}
		w := httptest.NewRecorder()
		requireHandler(ui, PermUI, &store.User{Role: string(RoleDeployer)}).
			ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 403 || !strings.Contains(w.Body.String(), "нет доступа") {
			t.Errorf("code = %d, body = %q", w.Code, w.Body.String())
		}
	})
}

// TestDisabledUserCannotAuthenticate: блокировка закрывает оба пути входа.
func TestDisabledUserCannotAuthenticate(t *testing.T) {
	a, _ := newAuth(t) // alice/secret, роль admin
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.CreateUser("bob", hash, string(RoleDeveloper)); err != nil {
		t.Fatal(err)
	}
	bob, err := a.Store.GetUser("bob")
	if err != nil || bob == nil {
		t.Fatal(err)
	}

	// Живая сессия до блокировки.
	lw := httptest.NewRecorder()
	if err := a.LoginUser(lw, "bob", "secret"); err != nil {
		t.Fatal(err)
	}
	cookie := lw.Header().Get("Set-Cookie")

	if err := a.Store.SetUserDisabled(bob.ID, true); err != nil {
		t.Fatal(err)
	}

	t.Run("session", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		a.RequireSession(echoUser(a)).ServeHTTP(w, r)
		if w.Code != http.StatusSeeOther {
			t.Errorf("code = %d, want 303 to /login", w.Code)
		}
	})

	t.Run("basic", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/apps", nil)
		r.SetBasicAuth("bob", "secret")
		w := httptest.NewRecorder()
		a.RequireBasic(echoUser(a)).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("code = %d, want 401", w.Code)
		}
	})

	t.Run("login", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := a.LoginUser(w, "bob", "secret"); err == nil {
			t.Error("disabled user logged in")
		}
		if w.Header().Get("Set-Cookie") != "" {
			t.Error("cookie set for disabled user")
		}
	})

	t.Run("unblocking restores access", func(t *testing.T) {
		if err := a.Store.SetUserDisabled(bob.ID, false); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/api/apps", nil)
		r.SetBasicAuth("bob", "secret")
		w := httptest.NewRecorder()
		a.RequireBasic(echoUser(a)).ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != "bob" {
			t.Errorf("code = %d, body = %q", w.Code, w.Body.String())
		}
	})
}
