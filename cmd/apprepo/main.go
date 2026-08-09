// Command apprepo is a binary artifact repository server.
//
// Subcommands:
//
//	serve (default)                     start the HTTP server
//	user add <username> [-role <role>]  create a user
//	user list                           list users
//	user role <username> <role>         change a user's role
//	user password <username>            set a user's password
//	user disable|enable <username>      block / unblock a user
//	user delete <username> -yes         delete a user
//
// The user subcommands are the emergency door into an installation nobody can
// log into any more: they talk to the database directly and need no session.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"apprepo/internal/app"
	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/naming"
	"apprepo/internal/store"

	"golang.org/x/term"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "serve":
			args = args[1:]
		case "user":
			userCmd(args[1:])
			return
		default:
			usagef("unknown command %q", args[0])
		}
	}
	serve(loadConfig(args))
}

// usage lists every subcommand; the role names come from auth.AllRoles so that
// adding a role does not need an edit here.
func usage() string {
	return fmt.Sprintf(`usage: apprepo [serve] [flags]
       apprepo user add <username> [-role <role>] [flags]
       apprepo user list [flags]
       apprepo user role <username> <role> [flags]
       apprepo user password <username> [flags]
       apprepo user disable <username> [flags]
       apprepo user enable <username> [flags]
       apprepo user delete <username> -yes [flags]

roles (increasing privilege): %s
  -role may be omitted only for the very first user, who is made an admin.
passwords come from APPREPO_PASSWORD or, on a terminal, an interactive prompt.
flags: the configuration flags of serve (-data-dir, -db, ...); see -h.
`, roleNames())
}

// roleNames renders the allowed roles for help and error texts.
func roleNames() string {
	names := make([]string, 0, len(auth.AllRoles()))
	for _, r := range auth.AllRoles() {
		names = append(names, string(r))
	}
	return strings.Join(names, ", ")
}

// usagef reports an argument error: message, usage text, exit code 2.
func usagef(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "apprepo: "+format+"\n", a...)
	fmt.Fprint(os.Stderr, usage())
	os.Exit(2)
}

// userCmd dispatches "apprepo user <subcommand>". Every subcommand takes its
// positional arguments first and the shared configuration flags after them.
func userCmd(args []string) {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "add":
		role, given, rest, err := cutFlag(args, "role")
		if err != nil {
			usagef("%v", err)
		}
		pos, rest := split(rest, 1, "user add <username> [-role <role>]")
		userAdd(pos[0], role, given, rest)
	case "list":
		userList(args)
	case "role":
		pos, rest := split(args, 2, "user role <username> <role>")
		userRole(pos[0], pos[1], rest)
	case "password":
		pos, rest := split(args, 1, "user password <username>")
		userPassword(pos[0], rest)
	case "disable", "enable":
		pos, rest := split(args, 1, "user "+sub+" <username>")
		userDisable(pos[0], sub == "disable", rest)
	case "delete":
		yes, rest := cutBoolFlag(args, "yes")
		pos, rest := split(rest, 1, "user delete <username> -yes")
		userDelete(pos[0], yes, rest)
	default:
		usagef("unknown user subcommand %q", sub)
	}
}

// split takes the first n arguments as positional ones and leaves the rest for
// config.Load. A flag in a positional slot is an argument error rather than a
// username: "user delete -yes" must not try to delete a user called "-yes".
func split(args []string, n int, form string) (pos, rest []string) {
	if len(args) < n {
		usagef("not enough arguments for: apprepo %s", form)
	}
	for _, a := range args[:n] {
		if strings.HasPrefix(a, "-") {
			usagef("missing argument (found flag %q) in: apprepo %s", a, form)
		}
	}
	return args[:n], args[n:]
}

// cutFlag pulls "-name value" or "-name=value" (also "--name") out of args and
// returns its value, whether it was given at all, and the remaining arguments.
// A subcommand flag has to be removed before the rest goes to config.Load,
// whose FlagSet rejects flags it does not know — and the flag package stops at
// the first positional argument, so "user add alice -role admin -db /tmp/x"
// cannot be parsed in one pass.
func cutFlag(args []string, name string) (value string, given bool, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		key, v, hasValue := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if !strings.HasPrefix(args[i], "-") || key != name {
			rest = append(rest, args[i])
			continue
		}
		given = true
		switch {
		case hasValue:
			value = v
		case i+1 < len(args):
			i++
			value = args[i]
		default:
			return "", false, nil, fmt.Errorf("flag -%s needs a value", name)
		}
	}
	return value, given, rest, nil
}

// cutBoolFlag removes a valueless flag such as -yes and reports its presence.
func cutBoolFlag(args []string, name string) (found bool, rest []string) {
	for _, a := range args {
		if a == "-"+name || a == "--"+name {
			found = true
			continue
		}
		rest = append(rest, a)
	}
	return found, rest
}

// loadConfig exits with code 2 on a bad configuration, printing the reason —
// except for flag syntax errors, which the flag package has already reported
// along with the usage text.
func loadConfig(args []string) config.Config {
	cfg, err := config.Load(args)
	if err != nil {
		if !errors.Is(err, config.ErrPrinted) {
			fmt.Fprintf(os.Stderr, "apprepo: %v\n", err)
		}
		os.Exit(2)
	}
	return cfg
}

// openStore honours the same configuration flags as serve (-data-dir, -db, …)
// and opens the database the server uses. The caller closes it.
func openStore(args []string) *store.Store {
	cfg := loadConfig(args)
	// 0700 — как в app.New (S1): при порядке «user add → serve» каталог БД
	// (по дефолту это и есть data-dir) не должен остаться мир-проходимым.
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		fatalf("%v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fatalf("%v", err) // store.Open уже называет путь — не дублируем
	}
	return st
}

// mustUser resolves a username to a user, since every store mutation takes an
// ID. A missing user is a plain error, not a panic. Имя нормализуется тем же
// naming.NormalizeUsername, что и при создании в CLI, API и UI: иначе учётку,
// заведённую как "ops", не нашли бы по " ops ".
func mustUser(st *store.Store, username string) *store.User {
	name, err := naming.NormalizeUsername(username)
	if err != nil {
		fatalf("%v", err)
	}
	u, err := st.GetUser(name)
	if err != nil {
		fatalf("%v", err)
	}
	if u == nil {
		// Печатается нормализованное имя: искали именно его, и в сценарии
		// разбора старых имён исходное "admin " читалось бы как «строки нет
		// вовсе», хотя в `user list` она видна (R6-qa круг 2).
		fatalf("user %q not found", name)
	}
	return u
}

// Тексты предупреждения об учётках, чьи имена появились до валидации из F12
// (пробелы, кириллица, двоеточие — до F12 API их принимал). mustUser в API и
// CLI прогоняет имя из пути через NormalizeUsername, поэтому по имени такая
// учётка больше не адресуется: управлять ею можно только в веб-интерфейсе, где
// учётка адресуется числовым id. Переименовывать их автоматически нельзя — это
// молча сломало бы Basic-креды в чужих пайплайнах, — поэтому администратору
// просто показывается список (R6-sec круг 2, N1).
//
// Текст называет только те операции, которые в продукте есть: смены имени
// учётки нет нигде (переименование существует лишь у приложений), поэтому
// советовать «rename … in the web UI» значит отправить администратора искать
// кнопку, которой нет (R6-sec круг 3, N2-а). Единственный путь — удалить и
// завести заново, и про смену Basic-кредов надо сказать сразу: иначе починка
// молча ломает CI.
//
// Случаи разделены: обещать «works and can sign in» про имя с двоеточием
// нельзя — по Basic такая учётка не входит никогда, и администратор, отложив
// её разбор, оставляет за ней уже сломанный пайплайн (R6-qa круг 2).
const (
	legacyNameWorking = "%d account(s) have legacy names (%s): they still work and can sign in, " +
		"but are not addressable by name from the API or CLI. "
	legacyNameBroken = "%d account(s) have a colon in the name (%s): HTTP Basic encodes " +
		"user:password, so these cannot sign in over Basic at all — with the deployer role, which " +
		"has no web UI either, such an account is dead; fix these first. "
	legacyNameFix = "There is no way to rename an account, so the only fix is to delete such an " +
		"account on the /users page of the web UI (where accounts are addressed by numeric id) and " +
		"create it again under a valid name; the new account gets new Basic credentials, so update " +
		"them wherever they are used (CI)"
)

// legacyNameWarning builds the warning for `user list` and for the serve log,
// or "" when the installation is healthy.
func legacyNameWarning(users []*store.User) string {
	working, broken := legacyNames(users)
	var msg string
	if len(working) > 0 {
		msg += fmt.Sprintf(legacyNameWorking, len(working), strings.Join(working, ", "))
	}
	if len(broken) > 0 {
		msg += fmt.Sprintf(legacyNameBroken, len(broken), strings.Join(broken, ", "))
	}
	if msg == "" {
		return ""
	}
	return "warning: " + msg + legacyNameFix
}

// legacyNames splits the quoted names that are not addressable by their own
// name any more into the ones that still work (пробелы, не-ASCII) and the ones
// that cannot authenticate over Basic at all (двоеточие). Отбор —
// naming.LegacyUsername/BrokenBasicUsername, тот же, что метит строки на
// странице /users; кавычки существенны: в таблице `user list` имя "admin "
// печатается неотличимо от "admin".
func legacyNames(users []*store.User) (working, broken []string) {
	for _, u := range users {
		switch {
		case !naming.LegacyUsername(u.Username):
		case naming.BrokenBasicUsername(u.Username):
			broken = append(broken, strconv.Quote(u.Username))
		default:
			working = append(working, strconv.Quote(u.Username))
		}
	}
	return working, broken
}

// report announces the outcome of a store mutation and exits on failure.
// ErrLastAdmin is a refusal, not a breakdown: nothing was changed, and the
// operator needs to know why rather than see a raw "last admin".
func report(err error, format string, a ...any) {
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		fatalf("refused: no active administrator would be left in the system")
	case err != nil:
		fatalf("%v", err)
	}
	fmt.Printf(format+"\n", a...)
}

func serve(cfg config.Config) {
	handler, st, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	if n, err := st.CountUsers(); err == nil && n == 0 {
		log.Print("no users exist yet; create one with: apprepo user add <username>")
	}
	if users, err := st.ListUsers(); err == nil {
		if warn := legacyNameWarning(users); warn != "" {
			log.Print(warn)
		}
	}

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
		// Без общего WriteTimeout: он рубил бы длинные скачивания больших файлов.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Print("shutting down")
		// Без дедлайна: Shutdown ждёт завершения активных ответов (graceful).
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("shutdown: %v", err)
		}
		close(done)
	}()

	log.Printf("apprepo listening on %s", cfg.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-done
}

// userAdd creates a user. Without -role the very first account becomes an
// admin — a fresh installation whose only user cannot manage users is unusable
// — while every later one has to name a role explicitly.
func userAdd(username, role string, roleGiven bool, args []string) {
	name, err := naming.NormalizeUsername(username)
	if err != nil {
		usagef("%v", err)
	}
	st := openStore(args)
	defer st.Close()
	if !roleGiven {
		n, err := st.CountUsers()
		if err != nil {
			fatalf("%v", err)
		}
		if n > 0 {
			usagef("-role is required (one of: %s)", roleNames())
		}
		role = string(auth.RoleAdmin)
	}
	r, err := auth.ParseRole(role)
	if err != nil {
		usagef("%v", err)
	}
	hash, err := auth.HashPassword(readPassword())
	if err != nil {
		fatalf("hash password: %v", err)
	}
	if err := st.CreateUser(name, hash, string(r)); errors.Is(err, store.ErrExists) {
		fatalf("user %q already exists", name)
	} else if err != nil {
		fatalf("create user: %v", err)
	}
	fmt.Printf("user %q created with role %s\n", name, r)
}

// userList prints the accounts. Password hashes are never shown.
func userList(args []string) {
	st := openStore(args)
	defer st.Close()
	users, err := st.ListUsers()
	if err != nil {
		fatalf("%v", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tROLE\tDISABLED\tCREATED")
	for _, u := range users {
		disabled := "no"
		if u.Disabled {
			disabled = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.Username, u.Role, disabled, u.CreatedAt)
	}
	if err := w.Flush(); err != nil {
		fatalf("%v", err)
	}
	// Предупреждение — в stderr, чтобы не портить таблицу для парсеров.
	if warn := legacyNameWarning(users); warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}
}

func userRole(username, role string, args []string) {
	r, err := auth.ParseRole(role)
	if err != nil {
		usagef("%v", err)
	}
	st := openStore(args)
	defer st.Close()
	u := mustUser(st, username)
	report(st.SetUserRole(u.ID, string(r)), "user %q is now %s", u.Username, r)
}

func userPassword(username string, args []string) {
	st := openStore(args)
	defer st.Close()
	u := mustUser(st, username)
	hash, err := auth.HashPassword(readPassword())
	if err != nil {
		fatalf("hash password: %v", err)
	}
	report(st.SetUserPassword(u.ID, hash), "password for user %q updated", u.Username)
}

func userDisable(username string, disable bool, args []string) {
	st := openStore(args)
	defer st.Close()
	u := mustUser(st, username)
	state := "enabled"
	if disable {
		state = "disabled"
	}
	report(st.SetUserDisabled(u.ID, disable), "user %q %s", u.Username, state)
}

// userDelete removes an account only with -yes: the CLI is run from scripts
// with no terminal to ask on, and a deleted account cannot be brought back.
func userDelete(username string, yes bool, args []string) {
	if !yes {
		usagef("refusing to delete user %q without -yes (deletion cannot be undone)", username)
	}
	st := openStore(args)
	defer st.Close()
	u := mustUser(st, username)
	report(st.DeleteUser(u.ID), "user %q deleted", u.Username)
}

// readPassword takes the password from APPREPO_PASSWORD or, on a terminal,
// prompts for it twice.
func readPassword() string {
	pw := os.Getenv("APPREPO_PASSWORD")
	if pw == "" {
		pw = promptPassword()
	}
	if pw == "" {
		fatalf("empty password (set APPREPO_PASSWORD or run interactively)")
	}
	// Та же политика, что в API и в UI (минимум и предел bcrypt): учётка,
	// заведённая из CLI, не должна быть слабее заведённой через HTTP.
	if err := naming.ValidatePassword(pw); err != nil {
		fatalf("%v", err)
	}
	return pw
}

func promptPassword() string {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return ""
	}
	fmt.Fprint(os.Stderr, "Password: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatalf("read password: %v", err)
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatalf("read password: %v", err)
	}
	if string(p1) != string(p2) {
		fatalf("passwords do not match")
	}
	return string(p1)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "apprepo: "+format+"\n", a...)
	os.Exit(1)
}
