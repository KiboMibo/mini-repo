package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apprepo/internal/store"
)

// newAuth поднимает store во временной БД и заводит пользователя alice.
func newAuth(t *testing.T) (*Auth, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser("alice", hash, string(RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	return &Auth{Store: st}, hash
}

// echoUser — хендлер за middleware: пишет имя пользователя из контекста.
func echoUser(a *Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := a.CurrentUser(r)
		if u == nil {
			http.Error(w, "no user in context", 500)
			return
		}
		w.Write([]byte(u.Username))
	})
}

func TestHashCheckPassword(t *testing.T) {
	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(hash, "pw") {
		t.Error("valid password rejected")
	}
	if CheckPassword(hash, "wrong") {
		t.Error("wrong password accepted")
	}
}

func TestRequireBasic(t *testing.T) {
	a, _ := newAuth(t)
	h := a.RequireBasic(echoUser(a))

	cases := []struct {
		name, user, pass string
		wantCode         int
	}{
		{"valid", "alice", "secret", 200},
		{"wrong password", "alice", "nope", 401},
		{"unknown user", "bob", "secret", 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/apps", nil)
			r.SetBasicAuth(c.user, c.pass)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.wantCode {
				t.Fatalf("code = %d, want %d", w.Code, c.wantCode)
			}
			if c.wantCode == 200 && w.Body.String() != "alice" {
				t.Errorf("user in context = %q, want alice", w.Body.String())
			}
			if c.wantCode == 401 {
				if got := w.Header().Get("WWW-Authenticate"); got != `Basic realm="apprepo"` {
					t.Errorf("WWW-Authenticate = %q", got)
				}
				if body := w.Body.String(); !strings.Contains(body, `"error":"unauthorized"`) {
					t.Errorf("401 body = %q, want JSON unauthorized", body)
				}
			}
		})
	}

	t.Run("no header", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/apps", nil))
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("code = %d, WWW-Authenticate = %q", w.Code, w.Header().Get("WWW-Authenticate"))
		}
	})
}

func TestRequireSession(t *testing.T) {
	a, _ := newAuth(t)
	h := a.RequireSession(echoUser(a))

	t.Run("no cookie redirects with next", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/apps/myapp?tab=1", nil))
		if w.Code != 303 {
			t.Fatalf("code = %d, want 303", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?next="+url.QueryEscape("/apps/myapp?tab=1") {
			t.Errorf("Location = %q", loc)
		}
	})

	t.Run("valid session passes", func(t *testing.T) {
		lw := httptest.NewRecorder()
		if err := a.LoginUser(lw, "alice", "secret"); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Cookie", lw.Header().Get("Set-Cookie"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != "alice" {
			t.Fatalf("code = %d, body = %q", w.Code, w.Body.String())
		}
	})

	t.Run("expired session redirects", func(t *testing.T) {
		token, err := a.Store.CreateSession(1, -time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 303 {
			t.Fatalf("code = %d, want 303", w.Code)
		}
	})

	t.Run("garbage cookie redirects", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "deadbeef"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 303 {
			t.Fatalf("code = %d, want 303", w.Code)
		}
	})
}

func TestNoOpenRedirect(t *testing.T) {
	a, _ := newAuth(t)
	h := a.RequireSession(echoUser(a))

	// absolute-form request target: RequestURI() отбрасывает scheme/host,
	// в next уходит только путь — хост злоумышленника не утекает.
	r := httptest.NewRequest("GET", "/", nil)
	r.URL, _ = url.Parse("https://evil.example/x")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if loc := w.Header().Get("Location"); loc != "/login?next=%2Fx" {
		t.Errorf("Location = %q, want /login?next=%%2Fx", loc)
	}

	for _, p := range []string{"https://evil.example/x", "//evil.example/x", `/\evil.example`, "not-a-path", ""} {
		if got := safeNext(p); got != "/" {
			t.Errorf("safeNext(%q) = %q, want /", p, got)
		}
	}
	if got := safeNext("/apps/x?y=1"); got != "/apps/x?y=1" {
		t.Errorf("safeNext relative = %q", got)
	}
}

func TestLoginUser(t *testing.T) {
	a, _ := newAuth(t)

	t.Run("wrong password: error, no cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := a.LoginUser(w, "alice", "nope"); err == nil {
			t.Fatal("want error")
		}
		if w.Header().Get("Set-Cookie") != "" {
			t.Errorf("cookie set on failed login: %q", w.Header().Get("Set-Cookie"))
		}
	})

	t.Run("success: cookie attributes", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := a.LoginUser(w, "alice", "secret"); err != nil {
			t.Fatal(err)
		}
		cs := w.Result().Cookies()
		if len(cs) != 1 {
			t.Fatalf("cookies = %d, want 1", len(cs))
		}
		c := cs[0]
		if c.Name != SessionCookie || c.Value == "" {
			t.Errorf("cookie %q=%q", c.Name, c.Value)
		}
		if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
			t.Errorf("attrs: HttpOnly=%v SameSite=%v Path=%q", c.HttpOnly, c.SameSite, c.Path)
		}
		if want := int((7 * 24 * time.Hour).Seconds()); c.MaxAge != want {
			t.Errorf("MaxAge = %d, want %d", c.MaxAge, want)
		}
		sess, err := a.Store.GetSession(c.Value)
		if err != nil || sess == nil {
			t.Fatalf("session not stored: %v %v", sess, err)
		}
	})
}

func TestLogoutUser(t *testing.T) {
	a, _ := newAuth(t)
	lw := httptest.NewRecorder()
	if err := a.LoginUser(lw, "alice", "secret"); err != nil {
		t.Fatal(err)
	}
	token := lw.Result().Cookies()[0].Value

	r := httptest.NewRequest("POST", "/logout", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	w := httptest.NewRecorder()
	a.LogoutUser(w, r)

	if sess, err := a.Store.GetSession(token); err != nil || sess != nil {
		t.Errorf("session survived logout: %v %v", sess, err)
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 || cs[0].MaxAge >= 0 || cs[0].Value != "" {
		t.Errorf("cookie not expired: %+v", cs)
	}
}
