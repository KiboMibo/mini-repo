package integration

// Настоящие бинарники, а не крафченые заголовки. Пакет internal/platform
// проверяет своё определение на собранных в памяти заголовках, а web/api — на
// коротких заглушках; здесь через оба интерфейса заливается ровно то, что
// выдаёт `go build` под чужую платформу, и проверяется вся цепочка: заливка →
// колонка в БД → объект версии → список версий → страница приложения.
// Задача R8-test.

import (
	"net/http"
	"strings"
	"testing"
)

// TestRealBinariesDetectedViaAPI: каждый собранный `go build` бинарник
// заливается через API без ?platform=, и сервер обязан назвать ровно ту
// платформу, под которую он собран. Это и есть обещание волны 8 «старые
// CI-скрипты с бинарниками не правятся ни одной строкой».
func TestRealBinariesDetectedViaAPI(t *testing.T) {
	skipIfShort(t, "кросс-сборка настоящих бинарников")
	e := newEnv(t, r8MaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("realbin")

	for i, tg := range r8Targets {
		t.Run(tg.String(), func(t *testing.T) {
			bin := crossBuild(t, tg)
			version := nthVersion(i)
			name := "realbin-" + tg.goos + "-" + tg.goarch
			resp := e.putWithPlatform("realbin", version, name, "", bin)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("PUT настоящего %s: status = %d, want 201; body: %s",
					tg, resp.StatusCode, readBody(t, resp))
			}
			obj := decodeJSON(t, resp)
			if obj["platform"] != tg.String() {
				t.Errorf("platform в ответе на заливку = %v, want %q", obj["platform"], tg)
			}
			if obj["sha256"] != sha256hex(bin) {
				t.Errorf("sha256 = %v, want %s (тело изменилось по дороге)", obj["sha256"], sha256hex(bin))
			}
			e.wantPlatformEverywhere(c, "realbin", version, tg.String(),
				"автоопределение "+tg.String()+" через API")
		})
	}
}

// TestRealBinariesDetectedViaUI: то же самое через форму интерфейса с полем
// «detect automatically» (обе половинки пусты). Отдельный тест, а не подтест
// предыдущего: определение в UI живёт в своём хендлере (web.saveUpload), и
// пропасть оно может независимо от API.
func TestRealBinariesDetectedViaUI(t *testing.T) {
	skipIfShort(t, "кросс-сборка настоящих бинарников")
	e := newEnv(t, r8MaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("uibin")

	for i, tg := range r8Targets {
		t.Run(tg.String(), func(t *testing.T) {
			bin := crossBuild(t, tg)
			version := nthVersion(i)
			resp := e.uploadUIPlatform(c, "uibin", version,
				"uibin-"+tg.goos+"-"+tg.goarch, bin, "", "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("заливка %s через UI: status = %d, want 303; body: %s",
					tg, resp.StatusCode, readBody(t, resp))
			}
			e.wantPlatformEverywhere(c, "uibin", version, tg.String(),
				"автоопределение "+tg.String()+" через UI")
		})
	}
}

// TestRealBinaryWithMatchingPlatformAccepted: заявленная платформа, совпадающая
// с определённой, — не конфликт. Проверяется отдельно от расхождения: если бы
// сравнение стояло «не равно» наоборот, тест на 409 всё равно был бы зелёным.
func TestRealBinaryWithMatchingPlatformAccepted(t *testing.T) {
	skipIfShort(t, "кросс-сборка настоящих бинарников")
	e := newEnv(t, r8MaxUpload)
	e.createApp("agree")
	tg := target{"linux", "arm64"}
	bin := crossBuild(t, tg)

	obj := e.mustPutVersion("agree", "1.0.0",
		"?filename=agree-bin&platform="+tg.String(), bin, "")
	if obj["platform"] != tg.String() {
		t.Errorf("platform = %v, want %q", obj["platform"], tg)
	}
}

// TestPlatformMismatchRefusedByAPI: заявленная платформа спорит с содержимым —
// 409 platform_mismatch, и на диске с БД не остаётся ничего. Тело нарочно
// настоящее: на заглушке определение молчит, и ветка расхождения недостижима.
func TestPlatformMismatchRefusedByAPI(t *testing.T) {
	skipIfShort(t, "кросс-сборка настоящих бинарников")
	e := newEnv(t, r8MaxUpload)
	e.createApp("mismatch")
	bin := crossBuild(t, target{"linux", "amd64"})

	resp := e.putWithPlatform("mismatch", "1.0.0", "mismatch-bin", "windows/amd64", bin)
	body := readBody(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("расхождение платформы: status = %d, want 409; body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"platform_mismatch"`) {
		t.Errorf("код ошибки не platform_mismatch; body: %s", body)
	}
	// Текст обязан назвать обе стороны — иначе по логу CI непонятно, кто прав.
	for _, want := range []string{"linux/amd64", "windows/amd64"} {
		if !strings.Contains(body, want) {
			t.Errorf("в тексте отказа нет %q; body: %s", want, body)
		}
	}
	e.wantNoVersion("mismatch", "1.0.0", "после 409 platform_mismatch")
}

// TestPlatformMismatchParityAPIvsUI: один и тот же файл с одной и той же чужой
// меткой, залитый двумя интерфейсами в одном окружении, обязан получить один и
// тот же вердикт. Утверждение нарочно слабее, чем «UI обязан отвечать 409»:
// команда вправе решить, что явно выбранная пара — это осознанное
// переопределение определения, но тогда так должны вести себя ОБА интерфейса.
// Разъехавшись, они дают дыру: то, что API не пускает как platform_mismatch,
// проходит через форму, и `windows/amd64` уезжает на linux-бинаре к тому, кто
// его скачает.
//
// Это та же пара, что и `api.uploadErr` ↔ `web.uploadError`: инвариант
// CLAUDE.md требует совпадения класса кода ответа на одну и ту же ошибку в API
// и UI.
func TestPlatformMismatchParityAPIvsUI(t *testing.T) {
	skipIfShort(t, "кросс-сборка настоящих бинарников")
	e := newEnv(t, r8MaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("mismatchpair")
	bin := crossBuild(t, target{"linux", "amd64"})
	const wrong = "windows/amd64"

	resp := e.putWithPlatform("mismatchpair", "1.0.0", "api-bin", wrong, bin)
	apiCode := resp.StatusCode
	apiBody := readBody(t, resp)
	resp.Body.Close()

	resp = e.uploadUIPlatform(c, "mismatchpair", "2.0.0", "ui-bin", bin, "windows", "amd64")
	uiCode := resp.StatusCode
	uiBody := readBody(t, resp)
	resp.Body.Close()

	apiRefused := apiCode >= 400 && apiCode < 500
	uiRefused := uiCode >= 400 && uiCode < 500
	if apiRefused != uiRefused {
		t.Errorf("расхождение интерфейсов на чужой метке %s: API %d (%s), UI %d (%s)",
			wrong, apiCode, verdictOf(apiRefused), uiCode, verdictOf(uiRefused))
	}

	for _, tc := range []struct {
		iface, version string
		refused        bool
		body           string
	}{
		{"API", "1.0.0", apiRefused, apiBody},
		{"UI", "2.0.0", uiRefused, uiBody},
	} {
		got := e.platformIfVersionExists("mismatchpair", tc.version)
		if tc.refused {
			if got != nil {
				t.Errorf("%s отказал, но версия сохранена с платформой %q", tc.iface, *got)
			}
			continue
		}
		if got != nil && *got == wrong {
			t.Errorf("%s принял чужую метку: у файла, собранного под linux/amd64, "+
				"в репозитории написано %q; ответ: %s", tc.iface, *got, firstLines(tc.body))
		}
	}
	e.wantNoTmpLeftovers("после заливок с чужой меткой платформы")
}

func verdictOf(refused bool) string {
	if refused {
		return "отказ"
	}
	return "принято"
}

// platformIfVersionExists returns the stored platform, or nil when the version
// was not created at all. Отличать нужно: «версии нет» — правильный исход,
// «версия есть с чужой меткой» — дефект.
func (e *env) platformIfVersionExists(appName, version string) *string {
	e.t.Helper()
	a, err := e.st.GetApp(appName)
	if err != nil {
		e.t.Fatalf("GetApp(%q): %v", appName, err)
	}
	if a == nil {
		return nil
	}
	v, err := e.st.GetVersion(a.ID, version)
	if err != nil {
		e.t.Fatalf("GetVersion(%q, %q): %v", appName, version, err)
	}
	if v == nil {
		return nil
	}
	return &v.Platform
}

// firstLines обрезает страницу до читаемого в логе куска.
func firstLines(s string) string {
	if len(s) > 600 {
		return s[:600] + "…"
	}
	return s
}
