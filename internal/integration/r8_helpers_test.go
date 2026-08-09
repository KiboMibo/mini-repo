package integration

// Хелперы сквозных сценариев волны 8 (платформа версии — T24/T25/T26, F20).
// Задача R8-test.
//
// Отличие от предыдущих волн: до сих пор ни один тест не заливал НАСТОЯЩИЙ
// бинарник. Всё, что проверяло автоопределение, обходилось крафчеными
// заголовками (`internal/platform`, `internal/web`) или самим `apprepo` под
// хостовую платформу (smoke). Крафченый заголовок доказывает, что разборщик
// читает поля; он не доказывает, что настоящий вывод `go build` под darwin/arm64
// опознаётся как darwin/arm64. Поэтому здесь бинарники собираются `go build`
// под несколько GOOS/GOARCH и заливаются через оба интерфейса целиком.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// r8MaxUpload — потолок тела для тестов волны 8: настоящий бинарник Go весит
// пару мегабайт, в общий defaultMaxUpload (1 MiB) он не влезает.
const r8MaxUpload = 32 << 20

// target — платформа сборки: то, что уходит в GOOS/GOARCH, и то же самое, что
// обязано приехать в поле platform.
type target struct{ goos, goarch string }

func (tg target) String() string { return tg.goos + "/" + tg.goarch }

// r8Targets — минимальный набор из задачи: три формата исполняемых файлов
// (ELF, Mach-O, PE) и две разрядности/архитектуры внутри ELF. Больше платформ
// проверяет модульный тест пакета; здесь важна не ширина словаря, а то, что
// цепочка «go build → заливка → БД → ответ API → страница UI» работает на
// настоящем файле.
var r8Targets = []target{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

// --- сборка настоящих бинарников ---

// tinyMain — исходник подопытного: минимальная программа, которую Go
// компилирует под любую платформу без CGO и без зависимостей. Собирать сам
// apprepo незачем: он весит на порядок больше, а заголовок у него ровно тот же.
const tinyMain = `package main

import "fmt"

func main() { fmt.Println("apprepo r8 test binary") }
`

var (
	buildMu    sync.Mutex
	buildCache = map[target][]byte{}
	buildSrc   string // каталог с go.mod подопытного, общий на прогон пакета
)

// crossBuild returns the bytes of a real executable built for tg. Сборки
// кешируются в памяти на прогон пакета: под каждую новую GOARCH Go
// докомпилирует стандартную библиотеку, и повторять это в каждом подтесте —
// минуты вместо секунд.
//
// CGO_ENABLED=0 обязателен: кросс-сборка с cgo требует чужого тулчейна, а
// заодно это ровно тот режим, в котором собирают артефакты в CI.
func crossBuild(t *testing.T, tg target) []byte {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	if b, ok := buildCache[tg]; ok {
		return b
	}
	if _, err := os.Stat(buildSrc); buildSrc == "" || err != nil {
		// Каталог с исходником общий на прогон пакета, но убирается вместе с
		// тем тестом, который его завёл (параллельных тестов в пакете нет).
		// Если следующий тест застанет его удалённым — заведёт заново; собранные
		// байты при этом уже лежат в памяти и не пересобираются.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(tinyMain), 0o600); err != nil {
			t.Fatalf("write main.go: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"),
			[]byte("module apprepotestbin\n\ngo 1.24\n"), 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		buildSrc = dir
	}
	out := filepath.Join(buildSrc, "out-"+tg.goos+"-"+tg.goarch)
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = buildSrc
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0", "GOOS="+tg.goos, "GOARCH="+tg.goarch, "GOFLAGS=")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", tg, err, msg)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read built binary %s: %v", tg, err)
	}
	os.Remove(out)
	buildCache[tg] = b
	return b
}

// skipIfShort пропускает тяжёлые сценарии волны 8 — те, что зовут `go build`
// или собирают предыдущий бинарник. Так же поступают TestUserAddCLI и
// TestCLIAccountsVisibleOverHTTP (конвенция проекта, CLAUDE.md).
func skipIfShort(t *testing.T, why string) {
	t.Helper()
	if testing.Short() {
		t.Skip(why + " — пропускаем в -short")
	}
}

// --- заливка с платформой ---

// putWithPlatform uploads body through the API with an explicit query, without
// env.putVersion's automatic &platform=any: волна 8 проверяет как раз то, что
// сервер решает про платформу сам.
func (e *env) putWithPlatform(app, version, filename, plat string, body []byte) *http.Response {
	e.t.Helper()
	q := "?filename=" + filename
	if plat != "" {
		q += "&platform=" + plat
	}
	return e.api("PUT", "/api/apps/"+app+"/versions/"+version+q, bytes.NewReader(body), nil)
}

// uploadUIPlatform posts the UI upload form with an explicit platform pair.
// Порядок частей — как в разметке (`csrf_token, version, sha256, platform_os,
// platform_arch, file`): хендлер читает части потоково и файл обязан быть
// последним (инвариант CLAUDE.md).
func (e *env) uploadUIPlatform(c *http.Client, appName, version, filename string, content []byte, goos, goarch string) *http.Response {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range [][2]string{
		{"csrf_token", e.csrfOf(c)},
		{"version", version},
		{"sha256", ""},
		{"platform_os", goos},
		{"platform_arch", goarch},
	} {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			e.t.Fatalf("WriteField %s: %v", f[0], err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		e.t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		e.t.Fatalf("write file part: %v", err)
	}
	mw.Close()
	req, err := http.NewRequest("POST", e.srv.URL+"/apps/"+appName+"/versions", &buf)
	if err != nil {
		e.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("POST upload: %v", err)
	}
	return resp
}

// nthVersion даёт уникальный semver на порядковый номер подтеста, чтобы
// заливки в одно приложение не сталкивались друг с другом.
func nthVersion(i int) string { return fmt.Sprintf("1.%d.0", i) }

// putHeadersOnly sends a PUT with a huge declared Content-Length and no body at
// all, and returns the status line and body if the server answered within wait
// (пустая строка означает «сервер ждал байты»). Так проверяется, что отказ
// стоит клиенту ноль трафика; тот же приём в F19.
func (e *env) putHeadersOnly(path string, wait time.Duration) (string, string) {
	e.t.Helper()
	const declared = 512 << 20
	conn := e.dialServer()
	req := "PUT " + path + " HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(e.srv.URL, "http://") + "\r\n" +
		"Authorization: " + basicAuthHeader() + "\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", declared) +
		"Content-Type: application/octet-stream\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		e.t.Fatalf("write headers: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		e.t.Fatalf("SetReadDeadline: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return "", ""
	}
	var body bytes.Buffer
	io.Copy(&body, br)
	conn.Close()
	return strings.TrimSpace(status), body.String()
}

// jsonField extracts one string field of a JSON body — тексты ошибок читаются
// разобранными, иначе экранирование кавычек внутри message ломает поиск.
func jsonField(t *testing.T, body, field string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("разбор JSON: %v; body: %s", err, body)
	}
	s, _ := m[field].(string)
	return s
}

// --- чтение платформы отовсюду ---

// platformInVersionObj reads the platform of one version through the API.
func (e *env) platformInVersionObj(app, version string) string {
	e.t.Helper()
	resp := e.api("GET", "/api/apps/"+app+"/versions/"+version, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET версии %s/%s: status = %d; body: %s", app, version, resp.StatusCode, readBody(e.t, resp))
	}
	m := decodeJSON(e.t, resp)
	p, ok := m["platform"]
	if !ok {
		e.t.Fatalf("в объекте версии %s/%s нет поля platform: %v", app, version, m)
	}
	s, _ := p.(string)
	return s
}

// platformInVersionList reads the platform of one version out of the list
// endpoint — отдельная сборка объекта, и разъехаться с одиночной она может.
func (e *env) platformInVersionList(app, version string) string {
	e.t.Helper()
	resp := e.api("GET", "/api/apps/"+app+"/versions", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET списка версий %s: status = %d", app, resp.StatusCode)
	}
	var items []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		e.t.Fatalf("разбор списка версий %s: %v", app, err)
	}
	for _, obj := range items {
		if obj["version"] != version {
			continue
		}
		p, ok := obj["platform"]
		if !ok {
			e.t.Fatalf("в элементе списка %s/%s нет поля platform: %v", app, version, obj)
		}
		s, _ := p.(string)
		return s
	}
	e.t.Fatalf("версии %s нет в списке версий %s: %v", version, app, items)
	return ""
}

// platformAs reads the version's platform as an arbitrary account (нужна там,
// где админа зовут не alice — например, в установке, поднятой предыдущим
// бинарником).
func (e *env) platformAs(cr cred, app, version string) string {
	e.t.Helper()
	code, body := e.statusAs(cr, "GET", "/api/apps/"+app+"/versions/"+version, nil, nil)
	if code != http.StatusOK {
		e.t.Fatalf("GET версии %s/%s: status = %d; body: %s", app, version, code, body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		e.t.Fatalf("разбор объекта версии: %v; body: %s", err, body)
	}
	p, ok := m["platform"]
	if !ok {
		e.t.Fatalf("в объекте версии %s/%s нет поля platform: %s", app, version, body)
	}
	s, _ := p.(string)
	return s
}

// downloadAs downloads the version's file as an arbitrary account.
func (e *env) downloadAs(cr cred, app, version string) []byte {
	e.t.Helper()
	resp := e.apiAs(cr, "GET", "/download/"+app+"/"+version, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET /download/%s/%s: status = %d", app, version, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("чтение скачанного: %v", err)
	}
	return b
}

// wantPlatformEverywhere asserts the platform is the same in the single version
// object, in the list and on the application page. Три места нарочно: поле
// собирается в versionObj (API ×2 маршрута) и в verRow (UI), и потерять его в
// одном из них можно независимо.
func (e *env) wantPlatformEverywhere(c *http.Client, app, version, want, why string) {
	e.t.Helper()
	if got := e.platformInVersionObj(app, version); got != want {
		e.t.Errorf("%s: platform в объекте версии = %q, want %q", why, got, want)
	}
	if got := e.platformInVersionList(app, version); got != want {
		e.t.Errorf("%s: platform в списке версий = %q, want %q", why, got, want)
	}
	if c != nil {
		e.wantPlatformOnPage(c, app, version, want, why)
	}
}

// wantPlatformOnPage asserts the application page shows the platform in the
// version's row. Проверяется именно строка версии, а не «текст встречается на
// странице»: выпадающие списки формы содержат все значения словаря, и поиск
// подстроки по всей странице зеленел бы всегда.
func (e *env) wantPlatformOnPage(c *http.Client, app, version, want, why string) {
	e.t.Helper()
	row := e.versionRowHTML(c, app, version)
	if want == "" {
		if !strings.Contains(row, "&mdash;") && !strings.Contains(row, "—") {
			e.t.Errorf("%s: в строке версии %s нет прочерка для неизвестной платформы; строка: %s", why, version, row)
		}
		return
	}
	if !strings.Contains(row, "<code>"+want+"</code>") {
		e.t.Errorf("%s: в строке версии %s нет платформы <code>%s</code>; строка: %s", why, version, want, row)
	}
}

// versionRowHTML returns the <tr> of the version from the application page.
// Разрезание по <tr> грубое, но достаточное: в таблице версий одна строка на
// версию, а модалки внутри неё — часть той же ячейки.
func (e *env) versionRowHTML(c *http.Client, app, version string) string {
	e.t.Helper()
	body := e.getPage(c, "/apps/"+app)
	for _, row := range strings.Split(body, "<tr>") {
		// Первая ячейка строки — номер версии; ищем её, а не вхождение
		// где угодно (номер встречается и в ссылке на скачивание).
		if strings.Contains(row, "<td>"+version+" ") || strings.Contains(row, "<td>"+version+"<") {
			return row
		}
	}
	e.t.Fatalf("на странице /apps/%s нет строки версии %s; страница: %s", app, version, body)
	return ""
}

// --- установка, поднятая предыдущим бинарником ---

// legacyInstall — каталог данных, набитый бинарником ДО волны 8, и креды его
// админа.
type legacyInstall struct {
	dataDir string
	cred    cred
}

// repoRoot returns the working tree root, so `git archive` and `go build` work
// no matter which directory the test binary was started from. Отсутствие
// репозитория — не провал сценария, а невозможность его поставить (архив
// исходников, выкачанный без .git): такой прогон пропускается вслух.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("сценарий обновления требует git-репозитория (git rev-parse: %v)", err)
	}
	return strings.TrimSpace(string(out))
}

// buildPreWave8Binary checks out the merge-base with develop into a temp dir
// and builds apprepo from it. Именно бинарник, а не рукописная схема (как в
// R6): волна 8 добавила и колонку, и backfill, и «предыдущая версия» должна
// быть настоящей — включая всё, что старый код писал в БД и на диск.
func buildPreWave8Binary(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	base, err := exec.Command("git", "-C", root, "merge-base", "HEAD", "develop").Output()
	if err != nil {
		t.Skipf("нет ветки develop, не с чем сравнивать предыдущую версию (git merge-base: %v)", err)
	}
	rev := strings.TrimSpace(string(base))

	src := t.TempDir()
	ar := exec.Command("git", "-C", root, "archive", rev)
	var arErr, tarErr bytes.Buffer
	ar.Stderr = &arErr
	tar := exec.Command("tar", "-x", "-C", src)
	tar.Stderr = &tarErr
	pipe, err := ar.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	tar.Stdin = pipe
	if err := tar.Start(); err != nil {
		t.Fatalf("tar start: %v", err)
	}
	if err := ar.Run(); err != nil {
		t.Fatalf("git archive %s: %v\n%s", rev, err, arErr.String())
	}
	if err := tar.Wait(); err != nil {
		t.Fatalf("tar wait: %v\n%s", err, tarErr.String())
	}

	bin := filepath.Join(src, "apprepo-prev")
	build := exec.Command("go", "build", "-o", bin, "./cmd/apprepo")
	build.Dir = src
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("сборка бинарника %s: %v\n%s", rev[:8], err, out)
	}
	return bin
}

// freePort asks the kernel for a port and gives it back. Окно между закрытием
// и стартом сервера теоретически позволяет кому-то занять порт; на практике в
// тестовой машине это единственный претендент, а альтернатива (передавать
// сокет в чужой процесс) требует правки продуктового кода.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// runLegacyServer starts the pre-wave-8 binary on dataDir and returns its base
// URL вместе с функцией остановки (она же вешается на t.Cleanup, повторный
// вызов безвреден).
func runLegacyServer(t *testing.T, bin, dataDir string) (string, func()) {
	t.Helper()
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	cmd := exec.Command(bin, "serve",
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-data-dir", dataDir,
		"-base-url", base)
	cmd.Env = os.Environ()
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("запуск предыдущего бинарника: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		// SIGTERM, а не Kill: у сервиса graceful shutdown, и оборванный на
		// полуслове процесс мог бы оставить БД в состоянии, которого в
		// проверяемом сценарии обновления не бывает.
		cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}
	t.Cleanup(stop)
	t.Cleanup(func() {
		if t.Failed() && log.Len() > 0 {
			t.Logf("журнал предыдущего бинарника:\n%s", log.String())
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base, stop
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	t.Fatalf("предыдущий бинарник не поднялся на %s; журнал:\n%s", base, log.String())
	return "", stop
}

// legacyPut uploads a file into the legacy installation over its own API, the
// way a CI script did it before wave 8: без ?platform=, которого тогда не было.
func legacyPut(t *testing.T, base string, cr cred, app, version, filename string, body []byte) {
	t.Helper()
	url := base + "/api/apps/" + app + "/versions/" + version + "?filename=" + filename
	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth(cr.user, cr.pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("заливка %s/%s предыдущим бинарником: status = %d, want 201",
			app, version, resp.StatusCode)
	}
}

// legacyPostJSON performs a JSON POST against the legacy installation.
func legacyPostJSON(t *testing.T, base string, cr cred, path, body string, want int) {
	t.Helper()
	req, err := http.NewRequest("POST", base+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth(cr.user, cr.pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("POST %s предыдущим бинарником: status = %d, want %d", path, resp.StatusCode, want)
	}
}

// legacyUpload — одна заливка в установку предыдущего бинарника.
type legacyUpload struct {
	version, filename string
	body              []byte
}

// seedPreWave8Install builds the previous binary, creates an account with its
// CLI, runs it as a server and fills the installation the way production was
// filled: приложение и версии, залитые кодом, который про платформу не знает
// вовсе. Сервер останавливается до возврата — дальше на этом же каталоге
// поднимается новый.
func seedPreWave8Install(t *testing.T, dataDir, appName, appDesc string, ups []legacyUpload) legacyInstall {
	t.Helper()
	bin := buildPreWave8Binary(t)
	cr := cred{"olduser", "old-password"}

	add := exec.Command(bin, "user", "add", cr.user, "-data-dir", dataDir)
	add.Env = append(os.Environ(), "APPREPO_PASSWORD="+cr.pass)
	add.Stdin = strings.NewReader("")
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("user add предыдущим бинарником: %v\n%s", err, out)
	}

	base, stop := runLegacyServer(t, bin, dataDir)
	legacyPostJSON(t, base, cr, "/api/apps",
		`{"name":"`+appName+`","description":"`+appDesc+`"}`, http.StatusCreated)
	for _, u := range ups {
		legacyPut(t, base, cr, appName, u.version, u.filename, u.body)
	}
	// Останавливаем до возврата: два процесса на одной SQLite-базе — не тот
	// сценарий, который проверяется, а обновление сервиса выглядит именно так.
	stop()
	return legacyInstall{dataDir: dataDir, cred: cr}
}
