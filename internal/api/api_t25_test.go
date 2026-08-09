package api_test

// T25: платформа версии в API. Заливка определяет платформу по самому файлу и
// требует ?platform= только там, где определить нечего (архив); поле platform
// есть во всех ответах с объектом версии; PATCH проставляет её руками.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// elfBin — минимальный валидный ELF-заголовок linux/amd64: debug/elf разбирает
// именно заголовок, поэтому «настоящий бинарник» здесь — это ровно эти 64
// байта. Тест с реально собранным бинарником ниже (TestPutVersionRealBinary).
func elfBin() string {
	var buf bytes.Buffer
	ident := make([]byte, 16)
	copy(ident, elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ident[elf.EI_OSABI] = byte(elf.ELFOSABI_NONE) // ELFOSABI_NONE → linux
	buf.Write(ident)
	le := binary.LittleEndian
	binary.Write(&buf, le, uint16(elf.ET_EXEC))
	binary.Write(&buf, le, uint16(elf.EM_X86_64))
	binary.Write(&buf, le, uint32(elf.EV_CURRENT))
	binary.Write(&buf, le, [3]uint64{}) // entry, phoff, shoff
	binary.Write(&buf, le, uint32(0))   // flags
	binary.Write(&buf, le, uint16(buf.Len()+6))
	binary.Write(&buf, le, [5]uint16{}) // phentsize, phnum, shentsize, shnum, shstrndx
	return buf.String()
}

// put заливает версию с произвольной строкой параметров запроса.
func put(t *testing.T, mux *http.ServeMux, app, version, query, content string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, mux, "PUT",
		"/api/apps/"+app+"/versions/"+version+"?filename="+app+"-"+version+query, content, nil)
}

// wantPlatform проверяет поле platform в объекте версии из ответа.
func wantPlatform(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if got := decode(t, w)["platform"]; got != want {
		t.Fatalf("platform = %v, want %q; body: %s", got, want, w.Body.String())
	}
}

// wantNothingStored: версии нет в БД, файла и каталога версии нет на диске, во
// временном каталоге не осталось недописанного тела. Каталог приложения после
// отката может остаться пустым — его создаёт публикация, и подчищается ровно
// то же, что и при неудачной вставке в БД (files.Remove снимает файл и
// каталог версии); пустой каталог не виден ни в API, ни в UI.
func wantNothingStored(t *testing.T, mux *http.ServeMux, dir, app, version string) {
	t.Helper()
	wantErr(t, do(t, mux, "GET", "/api/apps/"+app+"/versions/"+version, "", nil),
		http.StatusNotFound, "not_found")
	wantPath(t, filepath.Join(dir, app, version), false)
	if entries, err := os.ReadDir(filepath.Join(dir, app)); err == nil && len(entries) != 0 {
		t.Fatalf("каталог приложения не пуст после отказа: %v", entries)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, ".tmp")); err == nil && len(entries) != 0 {
		t.Fatalf("временный файл не убран: %v", entries)
	}
}

// TestPutVersionDetectsPlatform: голый бинарник заливается как раньше, без
// новых параметров, — ради этого автоопределение и делалось: старые CI-скрипты
// не правятся.
func TestPutVersionDetectsPlatform(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")

	w := put(t, mux, "myapp", "1.0.0", "", elfBin())
	wantStatus(t, w, http.StatusCreated)
	wantPlatform(t, w, "linux/amd64")
}

// TestPutVersionRealBinary — то же на настоящем собранном бинарнике, а не на
// крафченом заголовке. Требует тулчейна, поэтому пропускается с -short.
func TestPutVersionRealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: сборка бинарника")
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(src, "sample")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build недоступен: %v: %s", err, out)
	}
	content, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	mux := newMux(t)
	createApp(t, mux, "myapp")
	w := put(t, mux, "myapp", "1.0.0", "", string(content))
	wantStatus(t, w, http.StatusCreated)
	wantPlatform(t, w, runtime.GOOS+"/"+runtime.GOARCH)
}

// TestPutVersionArchiveNeedsPlatform: у архива платформы в файле нет —
// молчаливое «неизвестно» заменено внятным отказом, и после него не остаётся
// ни строки в БД, ни файла на диске.
func TestPutVersionArchiveNeedsPlatform(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "myapp")

	w := put(t, mux, "myapp", "1.0.0", "", "archive-bytes-not-a-binary")
	wantErr(t, w, http.StatusBadRequest, "platform_required")
	msg, _ := decode(t, w)["message"].(string)
	for _, want := range []string{
		"?platform=", // какой параметр
		"could not be detected",
		"nothing was stored", // что с уже залитым телом
		`"any"`,              // выход для файла без платформы
		"linux, darwin",      // допустимые значения
		"amd64",              //
		"-X PUT",             // готовая строка для лога CI
		"myapp-1.0.0",        //
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message не содержит %q; message = %q", want, msg)
		}
	}
	wantNothingStored(t, mux, dir, "myapp", "1.0.0")

	// Пустое значение = параметр не передан (в CI это незаданная переменная):
	// отказ тот же, а не «мусор в параметре».
	wantErr(t, put(t, mux, "myapp", "1.0.0", "&platform=", "archive-bytes"),
		http.StatusBadRequest, "platform_required")
	wantErr(t, put(t, mux, "myapp", "1.0.0", "&platform=%20%20", "archive-bytes"),
		http.StatusBadRequest, "platform_required")
}

// TestPutVersionExplicitPlatform: указанная руками платформа принимается там,
// где определить нечего, — и канонизируется, как semver.
func TestPutVersionExplicitPlatform(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")

	for i, c := range []struct{ query, want string }{
		{"&platform=linux/amd64", "linux/amd64"},
		{"&platform=any", "any"},
		{"&platform=%20Windows/AMD64%0A", "windows/amd64"}, // регистр и края
	} {
		version := fmt.Sprintf("1.0.%d", i)
		w := put(t, mux, "myapp", version, c.query, "archive-bytes")
		wantStatus(t, w, http.StatusCreated)
		wantPlatform(t, w, c.want)
	}
}

// TestPutVersionInvalidPlatform: мусор — 400 с перечислением допустимых
// значений, и это не стоит клиенту ни байта тела: параметр проверяется до
// чтения (тот же рубеж, что у ?filename=).
func TestPutVersionInvalidPlatform(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "myapp")

	for _, bad := range []string{"amd64", "linux%2F", "plan9%2Famd64", "linux%2Famd64%2Fx", "junk"} {
		w := put(t, mux, "myapp", "1.0.0", "&platform="+bad, "archive-bytes")
		wantErr(t, w, http.StatusBadRequest, "invalid_platform")
		if msg, _ := decode(t, w)["message"].(string); !strings.Contains(msg, "riscv64") {
			t.Errorf("%s: message не перечисляет допустимые значения: %q", bad, msg)
		}
	}
	wantNothingStored(t, mux, dir, "myapp", "1.0.0")

	// Ни байта тела: отказ обязан быть бесплатным для клиента (на архиве в
	// два гигабайта разница между «до» и «после» чтения — два гигабайта).
	body := &countingReader{r: strings.NewReader(strings.Repeat("x", 4096))}
	req := httptest.NewRequest("PUT",
		"/api/apps/myapp/versions/1.0.0?filename=myapp-1.0.0&platform=nonsense", body)
	req.SetBasicAuth(testUser, testPass)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	wantErr(t, w, http.StatusBadRequest, "invalid_platform")
	if body.n != 0 {
		t.Fatalf("прочитано %d байт тела до отказа, want 0", body.n)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestPutVersionPlatformMismatch: указанное расходится с содержимым — отказ, а
// не молчаливое доверие метке. Ошибка называет оба значения; исправляется либо
// параметром, либо PATCH'ем после заливки без параметра.
func TestPutVersionPlatformMismatch(t *testing.T) {
	mux, dir := newMuxDir(t)
	createApp(t, mux, "myapp")

	w := put(t, mux, "myapp", "1.0.0", "&platform=windows/amd64", elfBin())
	wantErr(t, w, http.StatusConflict, "platform_mismatch")
	msg, _ := decode(t, w)["message"].(string)
	for _, want := range []string{"linux/amd64", "windows/amd64", "nothing was stored", "PATCH"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message не содержит %q; message = %q", want, msg)
		}
	}
	wantNothingStored(t, mux, dir, "myapp", "1.0.0")

	// "any" на опознанном бинарнике — то же расхождение: файл зависит от ОС и
	// архитектуры, что бы ни утверждала метка.
	wantErr(t, put(t, mux, "myapp", "1.0.0", "&platform=any", elfBin()),
		http.StatusConflict, "platform_mismatch")

	// Совпало — 201.
	w = put(t, mux, "myapp", "1.0.0", "&platform=linux/amd64", elfBin())
	wantStatus(t, w, http.StatusCreated)
	wantPlatform(t, w, "linux/amd64")
}

// TestPatchVersionPlatform: ручная простановка и сброс.
func TestPatchVersionPlatform(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	wantStatus(t, put(t, mux, "myapp", "1.0.0", "&platform=any", "archive"), http.StatusCreated)
	const path = "/api/apps/myapp/versions/1.0.0"

	// Простановка: 200 с объектом версии целиком, значение каноническое.
	w := do(t, mux, "PATCH", path, `{"platform":"Linux/AMD64"}`, nil)
	wantStatus(t, w, http.StatusOK)
	wantPlatform(t, w, "linux/amd64")
	if m := decode(t, w); m["version"] != "1.0.0" || m["sha256"] == nil || m["is_latest"] != true {
		t.Fatalf("PATCH вернул не объект версии: %s", w.Body.String())
	}
	wantPlatform(t, do(t, mux, "GET", path, "", nil), "linux/amd64")

	// Сброс пустой строкой.
	wantPlatform(t, do(t, mux, "PATCH", path, `{"platform":""}`, nil), "")
	wantPlatform(t, do(t, mux, "GET", path, "", nil), "")

	// Тело без поля (и пустое тело) ничего не меняет.
	wantStatus(t, do(t, mux, "PATCH", path, `{"platform":"any"}`, nil), http.StatusOK)
	wantPlatform(t, do(t, mux, "PATCH", path, `{}`, nil), "any")
	wantPlatform(t, do(t, mux, "PATCH", path, "", nil), "any")

	// Мусор — 400, значение не меняется.
	wantErr(t, do(t, mux, "PATCH", path, `{"platform":"plan9/amd64"}`, nil),
		http.StatusBadRequest, "invalid_platform")
	wantPlatform(t, do(t, mux, "GET", path, "", nil), "any")

	// Чужие адреса и рубеж Content-Type (общий, из decodeJSON).
	wantErr(t, do(t, mux, "PATCH", "/api/apps/myapp/versions/9.9.9", `{"platform":"any"}`, nil),
		http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "PATCH", "/api/apps/nope/versions/1.0.0", `{"platform":"any"}`, nil),
		http.StatusNotFound, "not_found")
	wantErr(t, do(t, mux, "PATCH", "/api/apps/myapp/versions/abc", `{"platform":"any"}`, nil),
		http.StatusBadRequest, "invalid_version")
	wantErr(t, do(t, mux, "PATCH", path, `{"platform":"any"}`,
		map[string]string{"Content-Type": "text/plain"}),
		http.StatusUnsupportedMediaType, "unsupported_media_type")
}

// TestPlatformInAllVersionResponses: поле есть везде, где отдаётся объект
// версии, — на это закладывается UI.
func TestPlatformInAllVersionResponses(t *testing.T) {
	mux := newMux(t)
	createApp(t, mux, "myapp")
	wantStatus(t, put(t, mux, "myapp", "1.0.0", "", elfBin()), http.StatusCreated)
	wantStatus(t, put(t, mux, "myapp", "2.0.0", "&platform=any", "archive"), http.StatusCreated)

	wantPlatform(t, do(t, mux, "GET", "/api/apps/myapp/versions/1.0.0", "", nil), "linux/amd64")
	wantPlatform(t, do(t, mux, "GET", "/api/apps/myapp/latest", "", nil), "any")

	// Список версий и детальный объект приложения (versions[] + latest).
	w := do(t, mux, "GET", "/api/apps/myapp/versions", "", nil)
	wantStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), `"platform":"linux/amd64"`) ||
		!strings.Contains(w.Body.String(), `"platform":"any"`) {
		t.Fatalf("список версий без платформ: %s", w.Body.String())
	}
	w = do(t, mux, "GET", "/api/apps/myapp", "", nil)
	wantStatus(t, w, http.StatusOK)
	m := decode(t, w)
	latest, _ := m["latest"].(map[string]any)
	if latest == nil || latest["platform"] != "any" {
		t.Fatalf("latest без платформы: %s", w.Body.String())
	}
	versions, _ := m["versions"].([]any)
	if len(versions) != 2 {
		t.Fatalf("versions: %s", w.Body.String())
	}
	for _, v := range versions {
		if _, ok := v.(map[string]any)["platform"]; !ok {
			t.Fatalf("версия без поля platform: %s", w.Body.String())
		}
	}

	// Версия, залитая до появления платформы (backfill её не опознал), —
	// пустая строка, а не отсутствующее поле.
	wantPlatform(t, do(t, mux, "PATCH", "/api/apps/myapp/versions/2.0.0", `{"platform":""}`, nil), "")
}
