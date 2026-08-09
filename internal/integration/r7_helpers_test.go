package integration

// Хелперы сквозных сценариев волны 7 (T22 — прогресс загрузки в UI, T23 —
// обязательный ?filename=). Задача R7-test из docs/plans/2026-08-06-app-artifactory.md.
//
// Отличие от предыдущих волн: до сих пор все загрузки в тестах были плоскими
// «binary-of:app@version» — то есть ровно тем случаем, ради которого дефолт
// «{app}-{version}» когда-то и завели. Волна 7 существует ради многофайловых
// релизов, поэтому здесь появляются настоящие архивы: собираются в памяти,
// заливаются, скачиваются и распаковываются обратно.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// --- сборка архивов ---

// archiveEntry — файл внутри архива: путь (с вложенными каталогами) и тело.
type archiveEntry struct {
	path string
	body string
}

// multiFileRelease — содержимое «настоящего» релиза: вложенные каталоги,
// исполняемый файл, конфиг, README. Именно эта структура и не переживала
// дефолтное имя без расширения: скачанный файл нечем было открыть.
func multiFileRelease() []archiveEntry {
	return []archiveEntry{
		{"myapp/bin/myapp", "#!/bin/sh\nexec /usr/libexec/myapp \"$@\"\n"},
		{"myapp/bin/tools/migrate", "#!/bin/sh\nexec migrate --db \"$1\"\n"},
		{"myapp/etc/config.yaml", "listen: :8080\nlog_level: info\n"},
		{"myapp/share/doc/README.md", "# myapp\n\nMulti-file release.\n"},
	}
}

// tarGzBytes builds a real .tar.gz holding entries, with the directory records
// the nested paths imply. Собирается в тесте, а не лежит фикстурой в репозитории:
// бинарная фикстура не читается в ревью и незаметно протухает.
func tarGzBytes(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, dir := range dirsOf(entries) {
		if err := tw.WriteHeader(&tar.Header{
			Name: dir + "/", Typeflag: tar.TypeDir, Mode: 0o755,
		}); err != nil {
			t.Fatalf("tar dir %s: %v", dir, err)
		}
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.path, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.body)),
		}); err != nil {
			t.Fatalf("tar header %s: %v", e.path, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("tar body %s: %v", e.path, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// zipBytes builds a real .zip holding the same entries.
func zipBytes(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.path)
		if err != nil {
			t.Fatalf("zip create %s: %v", e.path, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("zip write %s: %v", e.path, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// dirsOf collects the nested directories the entry paths imply, parents first.
func dirsOf(entries []archiveEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		parts := strings.Split(e.path, "/")
		for i := 1; i < len(parts); i++ {
			d := strings.Join(parts[:i], "/")
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

// --- распаковка скачанного ---

// unTarGz reads a .tar.gz back into its regular-file entries, sorted by path.
// Проверка «архив распаковывается» намеренно делается настоящим распаковщиком:
// побайтовое равенство ловит порчу, но не отвечает на вопрос, остался ли файл
// архивом (например, после случайной перекодировки в текст).
func unTarGz(t *testing.T, b []byte) []archiveEntry {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out []archiveEntry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", h.Name, err)
		}
		out = append(out, archiveEntry{h.Name, string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// unZip reads a .zip back into its file entries, sorted by path.
func unZip(t *testing.T, b []byte) []archiveEntry {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	var out []archiveEntry
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		out = append(out, archiveEntry{f.Name, string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// wantSameEntries compares the unpacked archive with what went in.
func wantSameEntries(t *testing.T, got, want []archiveEntry, why string) {
	t.Helper()
	sorted := append([]archiveEntry(nil), want...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].path < sorted[j].path })
	if len(got) != len(sorted) {
		t.Fatalf("%s: в распакованном архиве %d файлов, want %d (%v)", why, len(got), len(sorted), got)
	}
	for i := range got {
		if got[i] != sorted[i] {
			t.Errorf("%s: файл %d = %+v, want %+v", why, i, got[i], sorted[i])
		}
	}
}

// --- проверки скачивания ---

// downloadHead performs the download and returns status, headers and body.
func (e *env) downloadFull(app, version string) (int, http.Header, []byte) {
	e.t.Helper()
	resp := e.download(app, version)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read download body: %v", err)
	}
	return resp.StatusCode, resp.Header, b
}

// wantDispositionName asserts Content-Disposition is an attachment carrying
// exactly the stored filename. Проверяется разобранный параметр, а не
// подстрока: «имя встречается где-то в заголовке» зеленеет и на обрезанном.
func wantDispositionName(t *testing.T, h http.Header, want string) {
	t.Helper()
	cd := h.Get("Content-Disposition")
	if cd == "" {
		t.Fatalf("нет заголовка Content-Disposition")
	}
	if !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want disposition attachment", cd)
	}
	if got := dispositionFilename(cd); got != want {
		t.Errorf("Content-Disposition filename = %q, want %q (заголовок целиком: %q)", got, want, cd)
	}
}

// dispositionFilename extracts the filename parameter, quoted or bare.
func dispositionFilename(cd string) string {
	for _, part := range strings.Split(cd, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "filename=") {
			continue
		}
		v := strings.TrimPrefix(part, "filename=")
		if unq, err := strconvUnquote(v); err == nil {
			return unq
		}
		return v
	}
	return ""
}

// strconvUnquote unquotes a quoted-string without pulling strconv semantics
// for backslash escapes we never emit.
func strconvUnquote(v string) (string, error) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`), nil
	}
	return "", errNotQuoted
}

var errNotQuoted = errNotQuotedType{}

type errNotQuotedType struct{}

func (errNotQuotedType) Error() string { return "not a quoted string" }

// wantContentType asserts the served type is one the extension implies.
// Список допустимых значений, а не одно: mime.TypeByExtension читает системную
// таблицу (/etc/mime.types), которая от машины к машине отличается, а когда
// расширение неизвестно, ServeContent определяет тип по сигнатуре файла.
// Жёсткое равенство сделало бы тест мигающим в другом образе CI.
func wantContentType(t *testing.T, h http.Header, allowed []string, why string) {
	t.Helper()
	ct := h.Get("Content-Type")
	base := strings.TrimSpace(strings.Split(ct, ";")[0])
	if base == "" {
		t.Errorf("%s: Content-Type пуст", why)
		return
	}
	for _, a := range allowed {
		if base == a {
			return
		}
	}
	t.Errorf("%s: Content-Type = %q, ожидался один из %v", why, ct, allowed)
}

var (
	gzipTypes = []string{"application/gzip", "application/x-gzip", "application/x-compressed-tar"}
	zipTypes  = []string{"application/zip", "application/x-zip-compressed"}
)

// --- проверки диска ---

// tmpEntries lists what is left in the storage scratch dir.
func (e *env) tmpEntries() []string {
	e.t.Helper()
	ents, err := os.ReadDir(filepath.Join(e.dataDir, ".tmp"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		e.t.Fatalf("ReadDir .tmp: %v", err)
	}
	out := make([]string, 0, len(ents))
	for _, en := range ents {
		out = append(out, en.Name())
	}
	return out
}

// wantNoTmpLeftovers asserts the scratch dir holds no abandoned upload.
func (e *env) wantNoTmpLeftovers(why string) {
	e.t.Helper()
	if left := e.tmpEntries(); len(left) != 0 {
		e.t.Errorf("%s: в .tmp остались временные файлы: %v", why, left)
	}
}

// wantNoVersion asserts the version exists neither in the database nor on disk.
// Три проверки вместе, потому что T23 обещает именно это: отказ до единого
// байта на диск. Строка без файла и файл без строки — разные болезни, и по
// одному только API их не различить.
func (e *env) wantNoVersion(appName, version, why string) {
	e.t.Helper()
	a, err := e.st.GetApp(appName)
	if err != nil {
		e.t.Fatalf("GetApp(%q): %v", appName, err)
	}
	if a != nil {
		v, err := e.st.GetVersion(a.ID, version)
		if err != nil {
			e.t.Fatalf("GetVersion(%q, %q): %v", appName, version, err)
		}
		if v != nil {
			e.t.Errorf("%s: версия %s/%s создана в БД (filename=%q)", why, appName, version, v.Filename)
		}
	}
	mustNotExist(e.t, e.versionDir(appName, version), why+": каталог версии")
	e.wantNoTmpLeftovers(why)
}

// --- загрузка без подстановки имени ---

// putVersionRaw uploads with the query string passed verbatim — including an
// empty one. Нужен отдельно от env.putVersion: тот подставляет ?filename= для
// тестов, которым имя безразлично, а здесь проверяется как раз его отсутствие.
func (e *env) putVersionRaw(app, version, query string, body []byte, sha string) *http.Response {
	e.t.Helper()
	hdr := map[string]string{}
	if sha != "" {
		hdr["X-Checksum-Sha256"] = sha
	}
	return e.api("PUT", "/api/apps/"+app+"/versions/"+version+query, bytes.NewReader(body), hdr)
}

// --- сырое соединение (обрыв посреди загрузки) ---

// dialServer opens a raw TCP connection to the httptest server, bypassing the
// HTTP client: обрыв «на середине тела» иначе не изобразить — http.Client
// закрывает соединение только после того, как запрос сформирован целиком.
func (e *env) dialServer() net.Conn {
	e.t.Helper()
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		e.t.Fatalf("dial %s: %v", addr, err)
	}
	e.t.Cleanup(func() { conn.Close() })
	return conn
}

// basicAuthHeader renders the Basic credentials of the test user.
func basicAuthHeader() string {
	req, _ := http.NewRequest("GET", "http://example/", nil)
	req.SetBasicAuth(testUser, testPass)
	return req.Header.Get("Authorization")
}
