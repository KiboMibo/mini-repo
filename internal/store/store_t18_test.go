package store

// T18: роли, управление учётками, миграция pre-T18 БД и защита последнего
// админа. Матрица прав — в internal/auth (роли там, store хранит строку).

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mustUser заводит пользователя и возвращает его id.
func mustUser(t *testing.T, s *Store, name, role string) int64 {
	t.Helper()
	if err := s.CreateUser(name, "hash-"+name, role); err != nil {
		t.Fatalf("CreateUser(%q, %q): %v", name, role, err)
	}
	u, err := s.GetUser(name)
	if err != nil || u == nil {
		t.Fatalf("GetUser(%q) = %v, %v", name, u, err)
	}
	return u.ID
}

func admins(t *testing.T, s *Store) int {
	t.Helper()
	n, err := s.CountAdmins()
	if err != nil {
		t.Fatalf("CountAdmins: %v", err)
	}
	return n
}

// TestMigratePreT18DB: БД, созданная кодом до T18 (users без role/disabled),
// открывается новым Open, пользователь остаётся на месте и становится admin.
func TestMigratePreT18DB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Схема ровно та, что была в schema.sql до T18.
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (
		  id            INTEGER PRIMARY KEY,
		  username      TEXT NOT NULL UNIQUE,
		  password_hash TEXT NOT NULL,
		  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
		);
		INSERT INTO users (username, password_hash) VALUES ('legacy', 'bcrypt-hash');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Дважды: миграция обязана быть идемпотентной.
	for i, pass := range []string{"first open", "reopen"} {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("%s: Open: %v", pass, err)
		}
		u, err := s.GetUser("legacy")
		if err != nil || u == nil {
			t.Fatalf("%s: GetUser = %v, %v", pass, u, err)
		}
		if u.PasswordHash != "bcrypt-hash" {
			t.Errorf("%s: password hash lost: %q", pass, u.PasswordHash)
		}
		if u.Role != roleAdmin {
			t.Errorf("%s: role = %q, want %q", pass, u.Role, roleAdmin)
		}
		if u.Disabled {
			t.Errorf("%s: existing user came out disabled", pass)
		}
		if n := admins(t, s); n != 1 {
			t.Errorf("%s: CountAdmins = %d, want 1", pass, n)
		}
		// Мигрированная таблица должна принимать новые вставки с ролью.
		if err := s.CreateUser("after-"+string(rune('a'+i)), "h", "developer"); err != nil {
			t.Errorf("%s: CreateUser after migration: %v", pass, err)
		}
		s.Close()
	}
}

func TestUsersCRUD(t *testing.T) {
	s, _ := openTemp(t)
	mustUser(t, s, "zoe", "developer")
	mustUser(t, s, "adam", roleAdmin)
	mustUser(t, s, "mia", "deployer")

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var got []string
	for _, u := range users {
		got = append(got, u.Username+":"+u.Role)
	}
	want := []string{"adam:admin", "mia:deployer", "zoe:developer"}
	if len(got) != len(want) {
		t.Fatalf("ListUsers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListUsers = %v, want %v (username asc)", got, want)
		}
	}
	if users[0].CreatedAt == "" {
		t.Error("CreatedAt empty")
	}

	id := users[2].ID // zoe
	byID, err := s.GetUserByID(id)
	if err != nil || byID == nil || byID.Username != "zoe" || byID.Role != "developer" {
		t.Fatalf("GetUserByID = %+v, %v", byID, err)
	}

	if err := s.SetUserRole(id, "maintainer"); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	if u, _ := s.GetUserByID(id); u.Role != "maintainer" {
		t.Errorf("role after SetUserRole = %q", u.Role)
	}

	if err := s.SetUserDisabled(id, true); err != nil {
		t.Fatalf("SetUserDisabled(true): %v", err)
	}
	if u, _ := s.GetUserByID(id); !u.Disabled {
		t.Error("Disabled not set")
	}
	if err := s.SetUserDisabled(id, false); err != nil {
		t.Fatalf("SetUserDisabled(false): %v", err)
	}
	if u, _ := s.GetUserByID(id); u.Disabled {
		t.Error("Disabled not cleared")
	}

	if err := s.DeleteUser(id); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if u, err := s.GetUserByID(id); u != nil || err != nil {
		t.Errorf("GetUserByID after delete = %v, %v, want nil, nil", u, err)
	}
	// Удаление отсутствующего — не ошибка, как и у DeleteApp.
	if err := s.DeleteUser(id); err != nil {
		t.Errorf("DeleteUser twice: %v", err)
	}
	// Операции по несуществующему id — ошибка, а не тихий успех.
	if err := s.SetUserRole(id, roleAdmin); err == nil {
		t.Error("SetUserRole on missing user: want error")
	}
	if err := s.SetUserPassword(id, "h"); err == nil {
		t.Error("SetUserPassword on missing user: want error")
	}
}

// TestCountAdminsIgnoresDisabled: заблокированный админ не держит установку.
func TestCountAdminsIgnoresDisabled(t *testing.T) {
	s, _ := openTemp(t)
	a1 := mustUser(t, s, "a1", roleAdmin)
	mustUser(t, s, "a2", roleAdmin)
	mustUser(t, s, "dev", "developer")
	if n := admins(t, s); n != 2 {
		t.Fatalf("CountAdmins = %d, want 2", n)
	}
	if err := s.SetUserDisabled(a1, true); err != nil {
		t.Fatal(err)
	}
	if n := admins(t, s); n != 1 {
		t.Fatalf("CountAdmins after disable = %d, want 1", n)
	}
}

// TestLastAdmin: удаление, блокировка и понижение последнего незаблокированного
// админа отбиваются ErrLastAdmin и ничего не меняют.
func TestLastAdmin(t *testing.T) {
	ops := map[string]func(*Store, int64) error{
		"delete":  (*Store).DeleteUser,
		"disable": func(s *Store, id int64) error { return s.SetUserDisabled(id, true) },
		"demote":  func(s *Store, id int64) error { return s.SetUserRole(id, "maintainer") },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			s, _ := openTemp(t)
			id := mustUser(t, s, "root", roleAdmin)
			mustUser(t, s, "dev", "developer") // не админ — не спасает

			if err := op(s, id); !errors.Is(err, ErrLastAdmin) {
				t.Fatalf("%s last admin = %v, want ErrLastAdmin", name, err)
			}
			u, err := s.GetUserByID(id)
			if err != nil || u == nil {
				t.Fatalf("admin gone after refused %s: %v, %v", name, u, err)
			}
			if u.Role != roleAdmin || u.Disabled {
				t.Errorf("admin changed after refused %s: role=%q disabled=%v", name, u.Role, u.Disabled)
			}
			if n := admins(t, s); n != 1 {
				t.Errorf("CountAdmins = %d, want 1", n)
			}

			// Второй админ снимает защиту.
			mustUser(t, s, "second", roleAdmin)
			if err := op(s, id); err != nil {
				t.Fatalf("%s with a second admin: %v", name, err)
			}
			if n := admins(t, s); n != 1 {
				t.Errorf("CountAdmins after %s = %d, want 1", name, n)
			}
		})
	}

	// Смена роли админа на admin (по сути no-op) защиту не трогает.
	t.Run("promote to admin is allowed", func(t *testing.T) {
		s, _ := openTemp(t)
		id := mustUser(t, s, "root", roleAdmin)
		if err := s.SetUserRole(id, roleAdmin); err != nil {
			t.Fatalf("SetUserRole(admin): %v", err)
		}
	})

	// Разблокировка последнего админа тоже разрешена.
	t.Run("enable is allowed", func(t *testing.T) {
		s, _ := openTemp(t)
		id := mustUser(t, s, "root", roleAdmin)
		second := mustUser(t, s, "second", roleAdmin)
		if err := s.SetUserDisabled(second, true); err != nil {
			t.Fatal(err)
		}
		if err := s.SetUserDisabled(id, true); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("disable last enabled admin = %v, want ErrLastAdmin", err)
		}
		if err := s.SetUserDisabled(second, false); err != nil {
			t.Fatalf("enable: %v", err)
		}
	})
}

// TestLastAdminConcurrent: два одновременных понижения двух админов не должны
// оставить установку без единого админа — проверка и запись атомарны.
// Раундов много: окно между «сколько админов» и UPDATE — микросекунды, с одной
// попытки его не поймать. Если writeTx перестанет быть BEGIN IMMEDIATE, тест
// падает — либо оба понижения проходят, либо второе приносит SQLITE_BUSY
// вместо ErrLastAdmin.
func TestLastAdminConcurrent(t *testing.T) {
	s, _ := openTemp(t)
	ids := []int64{mustUser(t, s, "a1", roleAdmin), mustUser(t, s, "a2", roleAdmin)}

	for round := 0; round < 200; round++ {
		for _, id := range ids { // вернуть обоих в админы
			if err := s.SetUserRole(id, roleAdmin); err != nil {
				t.Fatalf("round %d: restore admin: %v", round, err)
			}
		}
		var wg sync.WaitGroup
		errs := make([]error, len(ids))
		start := make(chan struct{})
		for i, id := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = s.SetUserRole(id, "developer")
			}()
		}
		close(start)
		wg.Wait()

		var refused int
		for i, err := range errs {
			switch {
			case err == nil:
			case errors.Is(err, ErrLastAdmin):
				refused++
			default:
				t.Fatalf("round %d: demote %d: unexpected error %v", round, i, err)
			}
		}
		if refused != 1 {
			t.Fatalf("round %d: refused = %d, want exactly 1", round, refused)
		}
		if n := admins(t, s); n != 1 {
			t.Fatalf("round %d: CountAdmins = %d, want 1 — installation left without an admin", round, n)
		}
	}
}

// TestSessionsDropped: блокировка, смена пароля и удаление гасят сессии
// (иначе разлогинить пользователя нечем).
func TestSessionsDropped(t *testing.T) {
	newSession := func(t *testing.T, s *Store, id int64) string {
		t.Helper()
		token, err := s.CreateSession(id, time.Hour)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if sess, err := s.GetSession(token); err != nil || sess == nil {
			t.Fatalf("fresh session not readable: %v, %v", sess, err)
		}
		return token
	}

	for _, c := range []struct {
		name string
		op   func(*Store, int64) error
	}{
		{"disable", func(s *Store, id int64) error { return s.SetUserDisabled(id, true) }},
		{"password reset", func(s *Store, id int64) error { return s.SetUserPassword(id, "new-hash") }},
		{"delete", (*Store).DeleteUser}, // каскадом по FK sessions.user_id
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := openTemp(t)
			mustUser(t, s, "keeper", roleAdmin) // чтобы не сработала защита админа
			id := mustUser(t, s, "victim", "developer")
			token := newSession(t, s, id)
			other := newSession(t, s, mustUser(t, s, "bystander", "developer"))

			if err := c.op(s, id); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if sess, err := s.GetSession(token); err != nil || sess != nil {
				t.Errorf("session survived %s: %v, %v", c.name, sess, err)
			}
			// Чужие сессии не задеты.
			if sess, err := s.GetSession(other); err != nil || sess == nil {
				t.Errorf("bystander session killed by %s: %v, %v", c.name, sess, err)
			}
			// Строка сессии именно удалена, а не просто не отдаётся.
			var n int
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, id).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%d session rows left after %s", n, c.name)
			}
		})
	}
}

// TestGetSessionDisabled: даже если строка сессии уцелела (её вставили в обход
// SetUserDisabled), заблокированный пользователь по ней не проходит.
func TestGetSessionDisabled(t *testing.T) {
	s, _ := openTemp(t)
	mustUser(t, s, "keeper", roleAdmin)
	id := mustUser(t, s, "victim", "developer")
	if err := s.SetUserDisabled(id, true); err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateSession(id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if sess, err := s.GetSession(token); err != nil || sess != nil {
		t.Fatalf("GetSession for disabled user = %v, %v, want nil, nil", sess, err)
	}
	if err := s.SetUserDisabled(id, false); err != nil {
		t.Fatal(err)
	}
	if sess, err := s.GetSession(token); err != nil || sess == nil {
		t.Fatalf("GetSession after unblock = %v, %v, want the session", sess, err)
	}
}
