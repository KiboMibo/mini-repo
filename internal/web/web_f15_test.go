package web_test

// F15 (R6-sec круг 3, N2-б): учётка со старым именем должна быть отличима от
// обычной прямо на странице /users — она печатается там же, где её и чинят, а
// `admin ` и `admin` иначе рисуются двумя одинаковыми строками.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"apprepo/internal/auth"
	"apprepo/internal/store"
)

// addRawUser creates a user bypassing name validation: имя такого вида сегодня
// не завести ни одним интерфейсом, но в базе, пережившей обновление, оно есть.
func (e *env) addRawUser(t *testing.T, username string) *store.User {
	t.Helper()
	hash, _ := auth.HashPassword("secret-pass")
	if err := e.st.CreateUser(username, hash, string(auth.RoleDeveloper)); err != nil {
		t.Fatal(err)
	}
	u, err := e.st.GetUser(username)
	if err != nil || u == nil {
		t.Fatalf("GetUser(%q): %v %v", username, u, err)
	}
	return u
}

// userRow returns the fragment of the page that belongs to the given user:
// строку таблицы опознаём по её собственной форме смены роли.
func userRow(t *testing.T, body string, u *store.User) string {
	t.Helper()
	for _, row := range strings.Split(body, "<tr") {
		if strings.Contains(row, fmt.Sprintf("/users/%d/role", u.ID)) {
			return row
		}
	}
	t.Fatalf("на странице нет строки пользователя %q (id %d)", u.Username, u.ID)
	return ""
}

func TestUsersPageMarksLegacyNames(t *testing.T) {
	e := newEnv(t)
	legacy := e.addRawUser(t, "admin ") // хвостовой пробел: двойник "admin"
	normal := e.addRawUser(t, "admin")

	rec := e.do(t, "GET", "/users", "", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	if got := userRow(t, body, legacy); !strings.Contains(got, "legacy name") {
		t.Errorf("строка учётки %q не помечена; row: %s", legacy.Username, got)
	}
	if got := userRow(t, body, normal); strings.Contains(got, "legacy name") {
		t.Errorf("обычная учётка %q помечена как легаси; row: %s", normal.Username, got)
	}
	// Пометка бессмысленна, если хвостовой пробел не видно: имя выводится в
	// кавычках (strconv.Quote), кавычки экранируются html/template.
	if want := `legacy name &#34;admin &#34;`; !strings.Contains(body, want) {
		t.Errorf("страница не показывает имя в кавычках (%s); body: %s", want, body)
	}
	// Пояснение над таблицей называет доступную операцию, а не переименование.
	for _, want := range []string{"rename an account: delete it here", "new Basic credentials"} {
		if !strings.Contains(body, want) {
			t.Errorf("на странице нет пояснения %q", want)
		}
	}
}

// В здоровой установке страница остаётся прежней: ни пометок, ни пояснения.
func TestUsersPageWithoutLegacyNames(t *testing.T) {
	e := newEnv(t)
	e.addRawUser(t, "ci-bot")
	body := e.do(t, "GET", "/users", "", nil, true).Body.String()
	if strings.Contains(body, "legacy name") {
		t.Errorf("страница без старых имён показывает пометку; body: %s", body)
	}
}
