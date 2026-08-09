// Package auth: bcrypt-пароли, сессии в SQLite и HTTP-middleware
// (session-кука для UI, Basic Auth для API/скачивания).
package auth

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"apprepo/internal/store"

	"golang.org/x/crypto/bcrypt"
)

// SessionCookie is the name of the UI session cookie.
const SessionCookie = "apprepo_session"

const sessionTTL = 7 * 24 * time.Hour

// ErrInvalidCredentials is returned by LoginUser on a wrong username/password.
var ErrInvalidCredentials = errors.New("invalid username or password")

// dummyHash прогоняется через bcrypt при отсутствии пользователя, чтобы
// не выдавать его существование по времени ответа.
var dummyHash, _ = HashPassword("timing-equalizer")

// HashPassword hashes pw with bcrypt at the default cost (10).
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// CheckPassword reports whether pw matches the bcrypt hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

type ctxKey struct{}

// Auth bundles the middlewares and login helpers around the store.
type Auth struct {
	Store *store.Store
	// Forbidden, если задан, отвечает на отказ Require вместо JSON по
	// умолчанию (см. Require).
	Forbidden http.HandlerFunc
}

// authenticate returns the user on valid credentials, ErrInvalidCredentials
// on wrong ones (bcrypt всегда прогоняется — тайминг не палит существование).
// Заблокированный пользователь неотличим от неверного пароля: проверка идёт
// после bcrypt, чтобы блокировку тоже не было видно по времени ответа.
func (a *Auth) authenticate(username, password string) (*store.User, error) {
	u, err := a.Store.GetUser(username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		CheckPassword(dummyHash, password)
		return nil, ErrInvalidCredentials
	}
	if !CheckPassword(u.PasswordHash, password) || u.Disabled {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// RequireBasic admits requests with valid HTTP Basic credentials and puts the
// user into the request context; otherwise 401 with WWW-Authenticate. Тело
// 401 — JSON по формату ошибок API (для /download контракт это допускает).
func (a *Auth) RequireBasic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username, password, ok := r.BasicAuth(); ok {
			u, err := a.authenticate(username, password)
			if err != nil && !errors.Is(err, ErrInvalidCredentials) {
				log.Printf("auth: %s %s: %v", r.Method, r.URL.Path, err)
				jsonError(w, http.StatusInternalServerError, "internal", "internal error")
				return
			}
			if u != nil {
				next.ServeHTTP(w, withUser(r, u))
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="apprepo"`)
		jsonError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
	})
}

// RequireSession admits requests with a valid session cookie and puts the
// user into the request context; otherwise 303 to /login?next={исходный путь}.
func (a *Auth) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(SessionCookie); err == nil {
			sess, err := a.Store.GetSession(c.Value)
			if err != nil {
				log.Printf("auth: %s %s: %v", r.Method, r.URL.Path, err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if sess != nil {
				u, err := a.Store.GetUserByID(sess.UserID)
				if err != nil {
					log.Printf("auth: %s %s: %v", r.Method, r.URL.Path, err)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				if u != nil {
					next.ServeHTTP(w, withUser(r, u))
					return
				}
			}
		}
		http.Redirect(w, r,
			"/login?next="+url.QueryEscape(safeNext(r.URL.RequestURI())),
			http.StatusSeeOther)
	})
}

// safeNext допускает только относительный путь внутри сайта: не "/..." или
// scheme-relative "//host" (и его вариант "/\host") → "/". Закрывает open
// redirect через next=https://evil (absolute-form request target).
func safeNext(p string) string {
	if !strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	return p
}

// CurrentUser returns the user placed into the context by a middleware,
// or nil outside of one.
func (a *Auth) CurrentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxKey{}).(*store.User)
	return u
}

// LoginUser verifies the credentials and, on success, creates a session and
// sets the session cookie (HttpOnly, SameSite=Lax, Path=/, 7 суток).
func (a *Auth) LoginUser(w http.ResponseWriter, username, password string) error {
	u, err := a.authenticate(username, password)
	if err != nil {
		return err
	}
	token, err := a.Store.CreateSession(u.ID, sessionTTL)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessionCookie(token, int(sessionTTL/time.Second)))
	return nil
}

// LogoutUser deletes the session (best effort) and expires the cookie.
func (a *Auth) LogoutUser(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		// Ошибка удаления не мешает разлогину: кука всё равно гасится,
		// а просроченная строка сессии подчистится в GetSession.
		_ = a.Store.DeleteSession(c.Value)
	}
	http.SetCookie(w, sessionCookie("", -1))
}

func sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

func withUser(r *http.Request, u *store.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, u))
}

func jsonError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Формат фиксирован контрактом; поля — литералы, экранирование не нужно.
	w.Write([]byte(`{"error":"` + code + `","message":"` + msg + `"}`))
}
