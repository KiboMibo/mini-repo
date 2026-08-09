// Package store is the SQLite persistence layer: users, sessions, apps and
// versions on top of database/sql with the pure-Go ncruces/go-sqlite3 driver.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"apprepo/internal/naming"
	"apprepo/internal/platform"

	"github.com/Masterminds/semver/v3"
	_ "github.com/ncruces/go-sqlite3/driver" // регистрирует драйвер "sqlite3"
	_ "github.com/ncruces/go-sqlite3/embed"  // WASM-сборка SQLite
)

//go:embed schema.sql
var schemaSQL string

// ErrExists is returned on unique-constraint duplicates (app name,
// app_id+version, username).
var ErrExists = errors.New("already exists")

// ErrLastAdmin is returned when an operation would leave the installation
// without a single enabled admin (demote, disable or delete the last one).
var ErrLastAdmin = errors.New("last admin")

// ErrNoUser is returned when a user write matched no row: the account was
// deleted between the caller's lookup and its update. Отдельный сорт ошибки,
// потому что это состояние («учётки уже нет»), а не сбой — вызывающие мапят
// её в 404, а не в 500.
var ErrNoUser = errors.New("user not found")

// timeFmt matches SQLite's datetime('now') output (UTC).
const timeFmt = "2006-01-02 15:04:05"

// roleAdmin — единственная роль, о которой знает store: на ней держится защита
// последнего админа. Полный набор ролей и права — в internal/auth (импортировать
// его сюда нельзя, auth уже импортирует store).
const roleAdmin = "admin"

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	Disabled     bool
	CreatedAt    string // как в БД: "2006-01-02 15:04:05" UTC
}

type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}

type App struct {
	ID                      int64
	Name                    string
	Description             string
	LatestOverrideVersionID *int64
	CreatedAt               time.Time
}

type Version struct {
	ID        int64
	AppID     int64
	Version   string // канонический semver без префикса v
	Filename  string
	SizeBytes int64
	SHA256    string // hex, нижний регистр
	Platform  string // "os/arch", "any" или "" — платформа неизвестна
	CreatedAt time.Time
}

type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path, applies the
// schema and PRAGMAs. Both are idempotent, so reopening an existing database
// is safe. Any error names the database file, so callers must not prepend the
// path again.
func Open(path string) (_ *Store, err error) {
	// Драйвер сообщает только «unable to open database file» — без имени файла
	// такой лог не диагностируется (F6). Путь известен здесь и всем вызывающим
	// сразу, поэтому называем файл в одном месте, а не в каждом из них.
	defer func() {
		if err != nil {
			err = fmt.Errorf("open database %s: %w"+
				" (check directory permissions; under systemd also ReadWritePaths=)", path, err)
		}
	}()
	// _pragma в DSN применяется драйвером к каждому соединению пула;
	// journal_mode=WAL при этом персистентен для файла БД. Пути с "?" или "#"
	// не поддерживаются (в конфиге таких не бывает).
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrateUsers(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate users: %w", err)
	}
	if err := migrateVersions(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate versions: %w", err)
	}
	// БД хранит bcrypt-хеши и живые сессионные токены: закрываем файлы от
	// чтения другими локальными пользователями (драйвер создаёт их по umask).
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, err
		}
	}
	return &Store{db: db}, nil
}

// migrateUsers brings a pre-T18 users table up to the current schema by adding
// the role and disabled columns (see addColumns for the mechanism).
//
// Существующие строки получают role='admin' из DEFAULT: до T18 все
// пользователи были равны и могли всё, миграция это поведение сохраняет.
func migrateUsers(db *sql.DB) error {
	return addColumns(db, "users", []column{
		{"role", `ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'`},
		{"disabled", `ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`},
	})
}

// migrateVersions brings a pre-T24 versions table up to the current schema by
// adding the platform column. Same mechanism and same idempotence as
// migrateUsers.
//
// Существующие строки получают пустую платформу — «неизвестно». Определить её по
// файлу отсюда нельзя (store не знает ни про files, ни про data-dir), этим
// занимается backfill в internal/app; что не опознается там, останется пустым
// до ручной простановки.
func migrateVersions(db *sql.DB) error {
	return addColumns(db, "versions", []column{
		{"platform", `ALTER TABLE versions ADD COLUMN platform TEXT NOT NULL DEFAULT ''`},
	})
}

type column struct{ name, ddl string }

// addColumns runs the DDL of every column that the table does not have yet.
// CREATE TABLE IF NOT EXISTS leaves an existing table alone and ALTER TABLE has
// no IF NOT EXISTS, so the columns already present are read first
// (pragma_table_info — табличная форма PRAGMA table_info). Idempotent: on a
// table that already has everything it only runs the one SELECT.
func addColumns(db *sql.DB, table string, cols []column) error {
	// table и ddl — константы кода, не пользовательский ввод: подставить имя
	// таблицы параметром SQLite всё равно не даёт.
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range cols {
		if have[c.name] {
			continue
		}
		if _, err := db.Exec(c.ddl); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// wrapExists maps SQLite unique-constraint violations to ErrExists.
func wrapExists(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrExists
	}
	return err
}

func parseTime(s string) time.Time {
	t, _ := time.ParseInLocation(timeFmt, s, time.UTC)
	return t
}

// --- users ---

const userCols = `id, username, password_hash, role, disabled, created_at`

// scanUser fills a User from a *sql.Row or *sql.Rows selected with userCols;
// a missing row is (nil, nil), as everywhere else in the package.
func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Disabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser inserts a user with the given role; ErrExists on a duplicate
// username. The role string is not validated here — auth.ParseRole is the
// gate; an unknown value simply grants nothing (Role.Can fails closed).
func (s *Store) CreateUser(username, passwordHash, role string) error {
	_, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
		username, passwordHash, role)
	return wrapExists(err)
}

// GetUser returns (nil, nil) when the user does not exist.
func (s *Store) GetUser(username string) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountAdmins counts admins that can actually log in: disabled ones do not
// keep the installation manageable and so do not count.
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0`, roleAdmin).Scan(&n)
	return n, err
}

// SetUserRole changes the user's role; ErrLastAdmin when it would demote the
// last enabled admin.
func (s *Store) SetUserRole(id int64, role string) error {
	return s.writeTx(func(tx *sql.Tx) error {
		if role != roleAdmin {
			if err := guardLastAdmin(tx, id); err != nil {
				return err
			}
		}
		return affected(tx.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id))
	})
}

// SetUserPassword replaces the password hash (admin reset or self-service
// change) and drops the user's sessions: a changed password must invalidate
// whoever is logged in with the old one.
func (s *Store) SetUserPassword(id int64, passwordHash string) error {
	return s.writeTx(func(tx *sql.Tx) error {
		if err := affected(tx.Exec(
			`UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id)); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
}

// SetUserDisabled blocks or unblocks the user without deleting the account.
// Blocking drops the user's sessions (otherwise an already logged-in browser
// would keep working) and returns ErrLastAdmin for the last enabled admin.
func (s *Store) SetUserDisabled(id int64, disabled bool) error {
	return s.writeTx(func(tx *sql.Tx) error {
		if disabled {
			if err := guardLastAdmin(tx, id); err != nil {
				return err
			}
		}
		if err := affected(tx.Exec(
			`UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)); err != nil {
			return err
		}
		if !disabled {
			return nil
		}
		_, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
}

// DeleteUser removes the account; its sessions go with it through the FK
// ON DELETE CASCADE on sessions.user_id. ErrLastAdmin for the last enabled
// admin. Deleting a missing user is not an error (as with DeleteApp).
func (s *Store) DeleteUser(id int64) error {
	return s.writeTx(func(tx *sql.Tx) error {
		if err := guardLastAdmin(tx, id); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id)
		return err
	})
}

// writeTx runs fn in a serializable transaction, which this driver starts as
// BEGIN IMMEDIATE — the write lock is taken before fn reads anything. That is
// what makes the last-admin check safe: two concurrent demotions are
// serialized, so the second one sees the first one's result and gets
// ErrLastAdmin instead of both reading "there are two admins" and leaving zero.
func (s *Store) writeTx(fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(),
		&sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback() // после успешного Commit — no-op, ошибка неинформативна
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// guardLastAdmin reports ErrLastAdmin when losing user id as an admin would
// leave none. Only meaningful inside writeTx. A missing user is not guarded:
// there is nothing to lose, and the caller's own statement reports it.
func guardLastAdmin(tx *sql.Tx, id int64) error {
	var role string
	var disabled bool
	err := tx.QueryRow(`SELECT role, disabled FROM users WHERE id = ?`, id).Scan(&role, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if role != roleAdmin || disabled {
		return nil
	}
	var n int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0`, roleAdmin).Scan(&n); err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// affected turns an UPDATE that matched nothing into ErrNoUser.
func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoUser
	}
	return nil
}

// --- sessions ---

// CreateSession issues a new random session token valid for ttl.
func (s *Store) CreateSession(userID int64, ttl time.Duration) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	expires := time.Now().UTC().Add(ttl).Format(timeFmt)
	if _, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expires); err != nil {
		return "", err
	}
	return token, nil
}

// GetSession returns (nil, nil) when the session does not exist, has expired
// or belongs to a disabled user; an expired row is deleted.
//
// Блокировка и так гасит сессии (SetUserDisabled), но join по users закрывает
// окно между выдачей сессии и блокировкой и делает отказ свойством запроса,
// а не порядка вызовов.
func (s *Store) GetSession(token string) (*Session, error) {
	var sess Session
	var expires string
	err := s.db.QueryRow(
		`SELECT s.token, s.user_id, s.expires_at FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token = ? AND u.disabled = 0`,
		token).Scan(&sess.Token, &sess.UserID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = parseTime(expires)
	if !sess.ExpiresAt.After(time.Now().UTC()) {
		return nil, s.DeleteSession(token)
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// --- apps ---

const appCols = `id, name, description, latest_override_version_id, created_at`

func scanApp(row *sql.Row) (*App, error) {
	var a App
	var created string
	var override sql.NullInt64
	err := row.Scan(&a.ID, &a.Name, &a.Description, &override, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if override.Valid {
		a.LatestOverrideVersionID = &override.Int64
	}
	a.CreatedAt = parseTime(created)
	return &a, nil
}

// CreateApp inserts a new app and returns it; ErrExists on duplicate name.
func (s *Store) CreateApp(name, description string) (*App, error) {
	// Как в UpdateApp: имя приложения — имя каталога, и на инвариант «в БД
	// только валидные имена» опирается files.RemoveApp (os.RemoveAll).
	if err := naming.ValidateAppName(name); err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO apps (name, description) VALUES (?, ?)`,
		name, description); err != nil {
		return nil, wrapExists(err)
	}
	return s.GetApp(name)
}

// GetApp returns (nil, nil) when the app does not exist.
func (s *Store) GetApp(name string) (*App, error) {
	return scanApp(s.db.QueryRow(
		`SELECT `+appCols+` FROM apps WHERE name = ?`, name))
}

// ListApps returns all apps ordered by name.
func (s *Store) ListApps() ([]*App, error) {
	rows, err := s.db.Query(`SELECT ` + appCols + ` FROM apps ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []*App
	for rows.Next() {
		var a App
		var created string
		var override sql.NullInt64
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &override, &created); err != nil {
			return nil, err
		}
		if override.Valid {
			a.LatestOverrideVersionID = &override.Int64
		}
		a.CreatedAt = parseTime(created)
		apps = append(apps, &a)
	}
	return apps, rows.Err()
}

// UpdateApp renames the app and replaces its description. ErrExists when the
// name is taken by another app. The single UPDATE is atomic on its own, so no
// explicit transaction is needed.
//
// The rename must be applied here first and only then on disk
// (files.RenameApp): a DB row pointing at a directory that no longer exists is
// worse than a stale directory. If the disk rename fails, the caller reverts
// by calling UpdateApp again with the previous name.
func (s *Store) UpdateApp(id int64, name, description string) error {
	// Дублируем проверку имени, как это делает files: имя приложения — имя
	// каталога, и мимо naming оно не должно попасть ни в БД, ни на диск.
	if err := naming.ValidateAppName(name); err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE apps SET name = ?, description = ? WHERE id = ?`, name, description, id)
	if err != nil {
		return wrapExists(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("app %d not found", id)
	}
	return nil
}

// DeleteApp removes the app together with all of its versions (FK ON DELETE
// CASCADE), in one atomic statement. Deleting a missing app is not an error.
// The caller removes {data-dir}/{app} afterwards (files.RemoveApp).
func (s *Store) DeleteApp(id int64) error {
	_, err := s.db.Exec(`DELETE FROM apps WHERE id = ?`, id)
	return err
}

// SetLatestOverride pins app's latest to the given version (nil clears the
// pin). The version must belong to the app.
func (s *Store) SetLatestOverride(appID int64, versionID *int64) error {
	if versionID != nil {
		var owner int64
		err := s.db.QueryRow(`SELECT app_id FROM versions WHERE id = ?`, *versionID).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != appID) {
			return fmt.Errorf("version %d does not belong to app %d", *versionID, appID)
		}
		if err != nil {
			return err
		}
	}
	res, err := s.db.Exec(
		`UPDATE apps SET latest_override_version_id = ? WHERE id = ?`, versionID, appID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("app %d not found", appID)
	}
	return nil
}

// --- versions ---

const versionCols = `id, app_id, version, filename, size_bytes, sha256, platform, created_at`

// scanVersion fills a Version from a *sql.Row or *sql.Rows selected with
// versionCols; a missing row is (nil, nil), as everywhere else in the package.
func scanVersion(sc interface{ Scan(...any) error }) (*Version, error) {
	var v Version
	var created string
	err := sc.Scan(&v.ID, &v.AppID, &v.Version, &v.Filename,
		&v.SizeBytes, &v.SHA256, &v.Platform, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.CreatedAt = parseTime(created)
	return &v, nil
}

// CreateVersion inserts a new version row; ErrExists on duplicate
// app_id+version. The version is canonicalized via naming.ValidateVersion.
func (s *Store) CreateVersion(appID int64, version, filename string, size int64, sha256 string) (*Version, error) {
	canonical, err := naming.ValidateVersion(version)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO versions (app_id, version, filename, size_bytes, sha256) VALUES (?, ?, ?, ?, ?)`,
		appID, canonical, filename, size, strings.ToLower(sha256)); err != nil {
		return nil, wrapExists(err)
	}
	return s.GetVersion(appID, canonical)
}

// GetVersion returns (nil, nil) when the version does not exist.
func (s *Store) GetVersion(appID int64, version string) (*Version, error) {
	canonical, err := naming.ValidateVersion(version)
	if err != nil {
		return nil, err
	}
	return scanVersion(s.db.QueryRow(
		`SELECT `+versionCols+` FROM versions WHERE app_id = ? AND version = ?`,
		appID, canonical))
}

// ListVersions returns the app's versions sorted by semver, newest first.
func (s *Store) ListVersions(appID int64) ([]*Version, error) {
	rows, err := s.db.Query(
		`SELECT `+versionCols+` FROM versions WHERE app_id = ?`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []*Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Semver-сортировка в Go, не строкой в SQL (1.10.0 > 1.9.1). Значения в БД
	// канонические (CreateVersion), поэтому парсинг не падает; на всякий случай
	// непарсибельное уходит в конец.
	parsed := make(map[string]*semver.Version, len(versions))
	for _, v := range versions {
		parsed[v.Version], _ = semver.NewVersion(v.Version)
	}
	sort.Slice(versions, func(i, j int) bool {
		a, b := parsed[versions[i].Version], parsed[versions[j].Version]
		if a == nil || b == nil {
			return b == nil && a != nil
		}
		return a.GreaterThan(b)
	})
	return versions, nil
}

// SetVersionPlatform sets (or clears) the version's target platform. An empty
// string is allowed and means "unknown" — that is how a wrongly set platform is
// reset. Anything else goes through platform.Parse and is stored canonical, so
// the column holds only values the UI lists know: the same reason CreateVersion
// canonicalizes semver instead of trusting the caller.
func (s *Store) SetVersionPlatform(id int64, p string) error {
	if p != "" {
		canonical, err := platform.Parse(p)
		if err != nil {
			return err
		}
		p = canonical
	}
	res, err := s.db.Exec(`UPDATE versions SET platform = ? WHERE id = ?`, p, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("version %d not found", id)
	}
	return nil
}

// DeleteVersion removes a version row (rollback of a failed insert, or an
// explicit delete). A pin on this version is cleared by the FK ON DELETE SET
// NULL on apps.latest_override_version_id, so latest resolves again to the
// maximum semver. Deleting a missing version is not an error. The caller
// removes {data-dir}/{app}/{version} afterwards (files.RemoveVersion).
func (s *Store) DeleteVersion(id int64) error {
	_, err := s.db.Exec(`DELETE FROM versions WHERE id = ?`, id)
	return err
}

// LatestVersion resolves the app's latest version: the override if pinned,
// otherwise the maximum semver. Returns (nil, nil) when there are no versions.
func (s *Store) LatestVersion(appID int64) (*Version, error) {
	var override sql.NullInt64
	err := s.db.QueryRow(
		`SELECT latest_override_version_id FROM apps WHERE id = ?`, appID).Scan(&override)
	if err != nil {
		return nil, err
	}
	if override.Valid {
		// Отсутствие строки — (nil, nil): FK с ON DELETE SET NULL делает это
		// недостижимым, но падать всё равно незачем.
		return scanVersion(s.db.QueryRow(
			`SELECT `+versionCols+` FROM versions WHERE id = ?`, override.Int64))
	}
	versions, err := s.ListVersions(appID)
	if err != nil || len(versions) == 0 {
		return nil, err
	}
	return versions[0], nil
}
