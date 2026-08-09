package main

import (
	"slices"
	"strings"
	"testing"

	"apprepo/internal/auth"
	"apprepo/internal/store"
)

// cutFlag and cutBoolFlag are the only hand-written argument parsing here: they
// have to lift a subcommand's own flags out of a line that also carries
// positional arguments and the configuration flags meant for config.Load.
func TestCutFlag(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		value string
		given bool
		rest  []string
		err   bool
	}{
		{name: "absent", args: []string{"alice", "-db", "x"}, rest: []string{"alice", "-db", "x"}},
		{name: "separate value", args: []string{"alice", "-role", "admin", "-db", "x"},
			value: "admin", given: true, rest: []string{"alice", "-db", "x"}},
		{name: "equals value", args: []string{"-role=admin", "alice"},
			value: "admin", given: true, rest: []string{"alice"}},
		{name: "double dash", args: []string{"--role", "developer", "alice"},
			value: "developer", given: true, rest: []string{"alice"}},
		{name: "before positional", args: []string{"-role", "admin", "alice"},
			value: "admin", given: true, rest: []string{"alice"}},
		// "-role=" is given but empty: it must reach ParseRole, not silently
		// fall back to the first-user default.
		{name: "empty value", args: []string{"-role=", "alice"}, given: true, rest: []string{"alice"}},
		{name: "no value", args: []string{"alice", "-role"}, err: true},
		// A flag whose name merely starts the same is not ours.
		{name: "prefix collision", args: []string{"-roles", "x"}, rest: []string{"-roles", "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, given, rest, err := cutFlag(tt.args, "role")
			if (err != nil) != tt.err {
				t.Fatalf("cutFlag(%q) error = %v, want error %v", tt.args, err, tt.err)
			}
			if tt.err {
				return
			}
			if value != tt.value || given != tt.given || !slices.Equal(rest, tt.rest) {
				t.Errorf("cutFlag(%q) = %q, %v, %q; want %q, %v, %q",
					tt.args, value, given, rest, tt.value, tt.given, tt.rest)
			}
		})
	}
}

func TestCutBoolFlag(t *testing.T) {
	tests := []struct {
		args  []string
		found bool
		rest  []string
	}{
		{args: []string{"bob", "-db", "x"}, rest: []string{"bob", "-db", "x"}},
		{args: []string{"bob", "-yes", "-db", "x"}, found: true, rest: []string{"bob", "-db", "x"}},
		{args: []string{"--yes", "bob"}, found: true, rest: []string{"bob"}},
		// The next argument is not a value: -yes takes none.
		{args: []string{"-yes", "bob", "-db", "x"}, found: true, rest: []string{"bob", "-db", "x"}},
	}
	for _, tt := range tests {
		found, rest := cutBoolFlag(tt.args, "yes")
		if found != tt.found || !slices.Equal(rest, tt.rest) {
			t.Errorf("cutBoolFlag(%q) = %v, %q; want %v, %q",
				tt.args, found, rest, tt.found, tt.rest)
		}
	}
}

// The help text must not grow a second, stale copy of the role list.
func TestRoleNamesCoversAllRoles(t *testing.T) {
	got := roleNames()
	for _, r := range auth.AllRoles() {
		if !strings.Contains(got, string(r)) {
			t.Errorf("roleNames() = %q, missing role %q", got, r)
		}
	}
	if !strings.Contains(usage(), got) {
		t.Errorf("usage() does not list the roles %q", got)
	}
}

// TestLegacyNames: учётки, заведённые до валидации имён (F12), из API и CLI по
// имени больше не адресуются, поэтому старт serve и `user list` показывают их
// администратору списком (R6-sec круг 2, N1). Здесь проверяется отбор: годные
// имена в предупреждение не попадают, негодные — попадают все.
func TestLegacyNames(t *testing.T) {
	users := []*store.User{
		{Username: "alice"}, {Username: "ci-bot"}, {Username: "a.b_c-9"},
		{Username: "аlice"},   // кириллическая "а" — визуальный двойник
		{Username: "admin "},  // хвостовой пробел: нормализуется в чужое имя
		{Username: "al ice"},  // пробел внутри
		{Username: "ci:bot"},  // двоеточие ломает HTTP Basic
		{Username: ".hidden"}, // не буква и не цифра в начале
	}
	// Имя с двоеточием отбирается отдельно: по Basic оно не входит вовсе, а
	// прочие старые имена работают (R6-qa круг 2).
	working, broken := legacyNames(users)
	wantWorking := []string{`"аlice"`, `"admin "`, `"al ice"`, `".hidden"`}
	if !slices.Equal(working, wantWorking) || !slices.Equal(broken, []string{`"ci:bot"`}) {
		t.Errorf("legacyNames() = %q, %q; want %q, [\"ci:bot\"]", working, broken, wantWorking)
	}
	if w, b := legacyNames(users[:3]); len(w)+len(b) != 0 {
		t.Errorf("legacyNames() пометила годные имена: %q %q", w, b)
	}
}

// TestLegacyNameWarning: предупреждение обещает ровно то, что есть. Учётке с
// пробелом мешает только адресация по имени, учётка с двоеточием по Basic не
// входит никогда — обещать ей «still work and can sign in» нельзя, иначе
// администратор откладывает разбор сломанного пайплайна (R6-qa круг 2).
func TestLegacyNameWarning(t *testing.T) {
	warn := func(names ...string) string {
		var users []*store.User
		for _, n := range names {
			users = append(users, &store.User{Username: n})
		}
		return legacyNameWarning(users)
	}
	if got := warn("alice", "ci-bot"); got != "" {
		t.Errorf("здоровая установка получила предупреждение: %q", got)
	}
	spaced := warn("admin ")
	if !strings.Contains(spaced, `"admin "`) || !strings.Contains(spaced, "still work and can sign in") {
		t.Errorf("предупреждение про рабочее старое имя = %q", spaced)
	}
	if strings.Contains(spaced, "cannot sign in over Basic") {
		t.Errorf("предупреждение без имён с двоеточием пугает отказом Basic: %q", spaced)
	}
	colon := warn("ci:bot")
	if !strings.Contains(colon, `"ci:bot"`) || !strings.Contains(colon, "cannot sign in over Basic at all") {
		t.Errorf("предупреждение про имя с двоеточием = %q", colon)
	}
	if strings.Contains(colon, "still work and can sign in") {
		t.Errorf("имени с двоеточием обещана работоспособность: %q", colon)
	}
	// Оба случая разом: каждое имя названо в своей половине, совет один.
	both := warn("admin ", "ci:bot")
	for _, want := range []string{"1 account(s) have legacy names", "1 account(s) have a colon"} {
		if !strings.Contains(both, want) {
			t.Errorf("предупреждение %q не содержит %q", both, want)
		}
	}
	if n := strings.Count(both, "delete such an account"); n != 1 {
		t.Errorf("совет по починке повторён %d раз(а): %q", n, both)
	}
}
