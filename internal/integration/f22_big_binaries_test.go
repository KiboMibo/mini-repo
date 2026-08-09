package integration

// Задача F22. Волна 8 уже проверяла настоящие бинарники (r8_binaries_test.go),
// но фикстурой была hello-world в полтора мегабайта — и ровно в этот зазор
// провалился дефект: у неурезанного `go build` таблица символов Mach-O и PE
// перерастала рубеж чтения примерно с 15 MB, и настоящие CI-артефакты под
// macOS и Windows переставали определяться (R8-qa, находка 1). Здесь то же
// сквозное «залил → определилось» на файлах в 27–29 MB.

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// bigMaxUpload — потолок тела: cmd/compile весит 27–29 MB, в r8MaxUpload (32 MB)
// он влезает, но без запаса.
const bigMaxUpload = 64 << 20

// bigTargets — три формата исполняемых файлов на крупных сборках. linux сюда
// не входит намеренно: ELF читал заголовок и до F22, дефекта на нём не было, а
// каждая лишняя цель — это докомпиляция стандартной библиотеки.
var bigTargets = []target{
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

var (
	bigMu    sync.Mutex
	bigCache = map[target][]byte{}
)

// buildBig кросс-собирает cmd/compile — крупный пакет, который есть в любой
// установке Go и не требует сети. Кеш на прогон пакета: сборка под каждую
// GOARCH тянет за собой стандартную библиотеку.
func buildBig(t *testing.T, tg target) []byte {
	t.Helper()
	bigMu.Lock()
	defer bigMu.Unlock()
	if b, ok := bigCache[tg]; ok {
		return b
	}
	out := filepath.Join(t.TempDir(), "compile-"+tg.goos+"-"+tg.goarch)
	cmd := exec.Command("go", "build", "-o", out, "cmd/compile")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0", "GOOS="+tg.goos, "GOARCH="+tg.goarch, "GOFLAGS=")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build cmd/compile под %s: %v\n%s", tg, err, msg)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	if len(b) < 15<<20 {
		t.Fatalf("фикстура %s весит %d байт: дефект, который тест ловит, начинается примерно с 15 MB", tg, len(b))
	}
	bigCache[tg] = b
	return b
}

// TestBigRealBinariesDetectedViaBothInterfaces: крупный неурезанный бинарник
// заливается без указания платформы и через API, и через форму UI, и сервер
// обязан назвать ту платформу, под которую он собран.
func TestBigRealBinariesDetectedViaBothInterfaces(t *testing.T) {
	skipIfShort(t, "кросс-сборка крупных бинарников")
	e := newEnv(t, bigMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("bigbin")

	for i, tg := range bigTargets {
		bin := buildBig(t, tg)
		name := "bigbin-" + tg.goos + "-" + tg.goarch

		t.Run("api/"+tg.String(), func(t *testing.T) {
			version := nthVersion(2 * i)
			resp := e.putWithPlatform("bigbin", version, name, "", bin)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("PUT %s (%d байт): status = %d, want 201; body: %s",
					tg, len(bin), resp.StatusCode, readBody(t, resp))
			}
			if obj := decodeJSON(t, resp); obj["platform"] != tg.String() {
				t.Errorf("platform = %v, want %q", obj["platform"], tg)
			}
			e.wantPlatformEverywhere(c, "bigbin", version, tg.String(),
				"крупный настоящий "+tg.String()+" через API")
		})

		t.Run("ui/"+tg.String(), func(t *testing.T) {
			version := nthVersion(2*i + 1)
			resp := e.uploadUIPlatform(c, "bigbin", version, name, bin, "", "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("заливка %s через UI: status = %d, want 303; body: %s",
					tg, resp.StatusCode, readBody(t, resp))
			}
			e.wantPlatformEverywhere(c, "bigbin", version, tg.String(),
				"крупный настоящий "+tg.String()+" через UI")
		})
	}
}

// TestBigRealBinaryMismatchRefused: расхождение метки и содержимого на крупном
// Mach-O тоже ловится. До F22 определить было нечего, и заявленная чушь
// проезжала молча — «защита от разъехавшейся метки на macOS и Windows не
// работает вовсе» (R8-qa, находка 1, побочный вывод).
func TestBigRealBinaryMismatchRefused(t *testing.T) {
	skipIfShort(t, "кросс-сборка крупных бинарников")
	e := newEnv(t, bigMaxUpload)
	e.createApp("bigmix")

	tg := target{"darwin", "arm64"}
	resp := e.putWithPlatform("bigmix", "1.0.0", "bigmix-bin", "linux/amd64", buildBig(t, tg))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", resp.StatusCode, readBody(t, resp))
	}
}
