// Package files stores version binaries on disk under
// {Root}/{app}/{version}/{filename}, streaming uploads through a temp file
// with SHA-256 verification.
package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"apprepo/internal/naming"
)

// ErrHashMismatch is returned by Prepare when the client-supplied SHA-256 does
// not match the streamed content.
var ErrHashMismatch = errors.New("sha256 mismatch")

// ErrFileExists is returned by Prepare/Commit when the destination file
// already exists, and by RenameApp when the destination directory does; the
// existing file is never touched (publication is an exclusive os.Link).
var ErrFileExists = errors.New("file already exists")

// ErrNotDirectory is returned by Prepare, Commit, RenameApp, RemoveApp and
// RemoveVersion when a path they write to, move or delete exists but is not a
// directory of ours. Root is the data dir and holds neighbours that are not
// app directories (the SQLite file and its -wal/-shm, .tmp), and an app name
// like "apprepo.db" passes naming — so the type of the target, not just its
// name, decides what may be touched. Every mutating operation of this package
// applies the same guard; callers map it to 409.
var ErrNotDirectory = errors.New("path is not an application directory")

// Storage saves and serves binaries under Root (the data dir). It must not be
// copied once used: locks guards the per-app mutexes below.
type Storage struct {
	Root string

	mu    sync.Mutex
	locks map[string]*appLock
}

// appLock is the per-app-name mutex plus its reference count, so that the map
// shrinks back to empty instead of growing one entry per name ever seen.
type appLock struct {
	sync.Mutex
	refs int
}

// lockApp serializes everything that moves an app's directory or publishes a
// file into it: rename, delete of the app or one version, and the publication
// step of an upload. The service is a single process (one binary, no
// horizontal replication — see CLAUDE.md and the systemd unit), so an
// in-process mutex is the whole story; nothing outside this process touches
// the data dir. The lock is never held while an upload body streams — only
// around the short publish step, see Upload.Commit.
func (st *Storage) lockApp(app string) (unlock func()) {
	st.mu.Lock()
	if st.locks == nil {
		st.locks = map[string]*appLock{}
	}
	l := st.locks[app]
	if l == nil {
		l = &appLock{}
		st.locks[app] = l
	}
	l.refs++
	st.mu.Unlock()

	l.Lock()
	return func() {
		l.Unlock()
		st.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(st.locks, app)
		}
		st.mu.Unlock()
	}
}

// lockApps locks two names in a fixed (sorted) order, so that renames in
// opposite directions cannot deadlock against each other.
func (st *Storage) lockApps(a, b string) (unlock func()) {
	if b < a {
		a, b = b, a
	}
	un1 := st.lockApp(a)
	un2 := st.lockApp(b)
	return func() { un2(); un1() }
}

// Path returns {Root}/{app}/{version}/{filename}. It does not validate its
// arguments; callers pass values already validated by Save or internal/naming.
func (st *Storage) Path(app, version, filename string) string {
	return filepath.Join(st.Root, app, version, filename)
}

// validate is the mandatory traversal guard: all three names must pass
// internal/naming even if the handler already checked them. The version must
// already be canonical so that Save and Path agree on the same directory.
func validate(app, version, filename string) error {
	if err := validateAppVersion(app, version); err != nil {
		return err
	}
	return naming.ValidateFilename(filename)
}

// validateAppVersion is the same guard for the two-name operations.
func validateAppVersion(app, version string) error {
	if err := naming.ValidateAppName(app); err != nil {
		return err
	}
	canon, err := naming.ValidateVersion(version)
	if err != nil {
		return err
	}
	if canon != version {
		return fmt.Errorf("version %q is not canonical (want %q)", version, canon)
	}
	return nil
}

// Save streams r into {Root}/{app}/{version}/{filename} and publishes it —
// Prepare followed by Commit without an extra check. Callers that serve HTTP
// uploads use the two steps directly: the app may be renamed or deleted while
// a large body streams, and only Commit's check sees that.
func (st *Storage) Save(app, version, filename string, r io.Reader, wantSHA256 string) (sha256hex string, size int64, err error) {
	u, err := st.Prepare(app, version, filename, r, wantSHA256)
	if err != nil {
		return "", 0, err
	}
	if err := u.Commit(nil); err != nil {
		return "", 0, err
	}
	return u.SHA256, u.Size, nil
}

// Upload is a body already streamed to a temp file and hashed, waiting to be
// published by Commit. Nothing under {Root}/{app} has been created yet.
type Upload struct {
	st                     *Storage
	app, version, filename string
	tmp                    string
	// SHA256 and Size describe the streamed content; valid after Prepare.
	SHA256 string
	Size   int64
}

// Prepare streams r into a temp file in {Root}/.tmp, computing SHA-256 on the
// fly. A non-empty wantSHA256 is compared case-insensitively; mismatch returns
// ErrHashMismatch. Target directories must be real directories or absent
// (ErrNotDirectory), and an already stored file is refused early with
// ErrFileExists. On any error the temp file is removed and no Upload is
// returned. No lock is taken here: the body may stream for minutes.
func (st *Storage) Prepare(app, version, filename string, r io.Reader, wantSHA256 string) (u *Upload, err error) {
	if err := validate(app, version, filename); err != nil {
		return nil, err
	}
	// Тот же рубеж по типу, что у удаления и переноса, — теперь и на записи:
	// решает тип каталога, а не его имя. Отсутствие каталога — норма (создаст
	// MkdirAll в Commit), присутствующий не-каталог — ErrNotDirectory (→ 409).
	// Без него MkdirAll резолвил бы подложенный на месте {Root}/{app} симлинк
	// и файл уезжал бы за пределы Root, а имя приложения, совпавшее с соседом
	// по data-dir (файлом БД), давало бы 500 вместо конфликта. Проверка стоит
	// до прогона байтов: отказывать дёшево. Commit повторит её под замком.
	if err := st.checkDirs(app, version); err != nil {
		return nil, err
	}
	// Быстрый отказ до прогона байтов; авторитетна атомарная публикация ниже.
	if _, err := os.Stat(st.Path(app, version, filename)); err == nil {
		return nil, ErrFileExists
	}
	tmpDir := filepath.Join(st.Root, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(tmpDir, "upload-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	size, err := io.Copy(tmp, io.TeeReader(r, h))
	if err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if wantSHA256 != "" && !strings.EqualFold(wantSHA256, sum) {
		err = ErrHashMismatch
		return nil, err
	}
	if err = tmp.Close(); err != nil {
		return nil, err
	}
	return &Upload{st: st, app: app, version: version, filename: filename,
		tmp: tmp.Name(), SHA256: sum, Size: size}, nil
}

// Path returns the temp file the body was streamed into, so that a caller can
// look inside the content before publishing it — determining the platform of a
// binary is such a look. Valid until Commit or Discard; the file is a plain
// regular file inside {Root}/.tmp and must be treated as read-only.
//
// Нужно ровно затем, чтобы решение «принимать или отказать» принималось ДО
// публикации: разбор опубликованного файла растягивал окно между Commit и
// созданием строки в БД до секунд, и удаление приложения внутри него давало
// 500 (R8-sec S2).
func (u *Upload) Path() string { return u.tmp }

// Discard removes the temp file of an upload that will not be published.
// Commit removes it too, so exactly one of the two is called for every Upload.
func (u *Upload) Discard() error { return os.Remove(u.tmp) }

// Commit publishes the streamed file under the app lock, so that no rename or
// delete of the same app can interleave with the directory being created and
// the file being linked into it. A non-nil check runs under that lock and must
// report whether the app still exists under the same name: the row may have
// been renamed away while the body streamed, and publishing then would leave
// the file in a directory no row points at. Its error is returned as is.
// The temp file is removed either way; the Upload must not be reused.
func (u *Upload) Commit(check func() error) error {
	defer os.Remove(u.tmp)
	unlock := u.st.lockApp(u.app)
	defer unlock()
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	if err := u.st.checkDirs(u.app, u.version); err != nil {
		return err
	}
	dst := u.st.Path(u.app, u.version, u.filename)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Атомарно-эксклюзивная публикация: Link падает с EEXIST, ничего не
	// перезаписывая, — проигравший гонки не касается файла победителя
	// (Rename молча перезаписывал бы dst).
	if err := os.Link(u.tmp, dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrFileExists
		}
		return err
	}
	return nil
}

// checkDirs refuses to write when the app or version directory exists but is
// not a real directory of ours.
func (st *Storage) checkDirs(app, version string) error {
	for _, dir := range []string{filepath.Join(st.Root, app), filepath.Join(st.Root, app, version)} {
		if _, err := isDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes the stored file (rollback for a failed DB insert) and prunes
// the version directory if it became empty.
func (st *Storage) Remove(app, version, filename string) error {
	if err := validate(app, version, filename); err != nil {
		return err
	}
	p := st.Path(app, version, filename)
	if err := os.Remove(p); err != nil {
		return err
	}
	os.Remove(filepath.Dir(p)) // best effort: fails (ignored) when non-empty
	return nil
}

// RenameApp renames {Root}/{oldName} to {Root}/{newName}. An app without
// versions has no directory yet — a missing source is not an error. An
// existing destination is refused with ErrFileExists: nothing is overwritten.
// The source must be a real directory of ours: os.Rename moves whatever lies
// at that path, so without the isDir guard an app named like a neighbour in
// the data dir (the SQLite file, its -wal/-shm) would carry that file away —
// ErrNotDirectory, nothing is moved.
// Callers must rename the DB row first (see store.UpdateApp) so that a failure
// here never leaves a row pointing at a directory that is gone.
func (st *Storage) RenameApp(oldName, newName string) error {
	if err := naming.ValidateAppName(oldName); err != nil {
		return err
	}
	if err := naming.ValidateAppName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	// Оба имени: и каталог-источник, и каталог-приёмник не должны двигаться
	// или наполняться публикацией, пока идёт перенос.
	defer st.lockApps(oldName, newName)()
	dst := filepath.Join(st.Root, newName)
	// os.Rename would happily replace an empty directory, so refuse up front.
	// Stdlib has no RENAME_NOREPLACE, so this check is not atomic by itself —
	// concurrent creators of the same path are held off by the app lock above,
	// and the DB UNIQUE on apps.name serializes the rows.
	if _, err := os.Lstat(dst); err == nil {
		return ErrFileExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	src := filepath.Join(st.Root, oldName)
	// Тот же рубеж, что у удаления: решает тип источника, а не его имя.
	// Отсутствие каталога — приложение ещё без версий, это не ошибка (isDir
	// даёт (false, nil)); присутствующий не-каталог — ErrNotDirectory.
	if ok, err := isDir(src); !ok {
		return err
	}
	return os.Rename(src, dst)
}

// isDir reports whether p is a real directory (os.Lstat: a symlink is not one,
// even when it points at a directory). Missing is (false, nil) — deleting what
// is not there is a no-op, not an error. Anything else present is
// ErrNotDirectory: it belongs to somebody else and must not be removed.
func isDir(p string) (bool, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s: %w", p, ErrNotDirectory)
	}
	return true, nil
}

// RemoveApp deletes {Root}/{app} with everything inside it, including stray
// files that are not tracked in the database. A missing directory is not an
// error; a non-directory at that path is ErrNotDirectory and is left alone.
func (st *Storage) RemoveApp(app string) error {
	if err := naming.ValidateAppName(app); err != nil {
		return err
	}
	defer st.lockApp(app)()
	p := filepath.Join(st.Root, app)
	if ok, err := isDir(p); !ok {
		return err
	}
	return os.RemoveAll(p)
}

// RemoveVersion deletes {Root}/{app}/{version} with everything inside it. The
// version must already be canonical. A missing directory is not an error.
// Both the app directory and the version directory must be real directories:
// os.RemoveAll resolves symlinked parents, so a symlink at {Root}/{app} would
// otherwise delete a directory outside Root.
func (st *Storage) RemoveVersion(app, version string) error {
	if err := validateAppVersion(app, version); err != nil {
		return err
	}
	defer st.lockApp(app)()
	appDir := filepath.Join(st.Root, app)
	if ok, err := isDir(appDir); !ok {
		return err
	}
	p := filepath.Join(appDir, version)
	if ok, err := isDir(p); !ok {
		return err
	}
	return os.RemoveAll(p)
}
