package integration

// Ручная простановка платформы и согласованность интерфейсов: проставленное
// через API обязано быть видно в UI и наоборот — колонка одна, и разъехаться
// они могут только из-за разной канонизации или разного понимания «сброса».
// Задача R8-test.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// patchPlatform sends PATCH /api/apps/{app}/versions/{version} with the given
// JSON body and returns status and body.
func (e *env) patchPlatform(app, version, body string) (int, string) {
	e.t.Helper()
	return e.statusAs(adminCred, "PATCH",
		"/api/apps/"+app+"/versions/"+version, strings.NewReader(body), jsonHdr)
}

// setPlatformUI submits the row dialog of the application page.
func (e *env) setPlatformUI(c *http.Client, app, version, goos, goarch string) (int, string) {
	e.t.Helper()
	return e.uiPostStatus(c, "/apps/"+app+"/versions/"+version+"/platform",
		url.Values{"platform_os": {goos}, "platform_arch": {goarch}})
}

// TestManualPlatformRoundTripBetweenAPIAndUI: проставили в одном интерфейсе —
// видно в другом, и так в обе стороны, включая сброс в «неизвестно».
func TestManualPlatformRoundTripBetweenAPIAndUI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("manual")
	// Тело — текстовая заглушка: определять по ней нечего, и версия заводится
	// с «any», как это делают остальные тесты пакета (F20).
	e.seed("manual", "1.0.0")

	steps := []struct {
		name     string
		set      func(t *testing.T)
		want     string
		wantJSON string
	}{
		{
			name: "API ставит linux/arm64",
			set: func(t *testing.T) {
				code, body := e.patchPlatform("manual", "1.0.0", `{"platform":"linux/arm64"}`)
				if code != http.StatusOK {
					t.Fatalf("PATCH: status = %d, want 200; body: %s", code, body)
				}
				if !strings.Contains(body, `"platform":"linux/arm64"`) {
					t.Errorf("в ответе PATCH нет новой платформы; body: %s", body)
				}
			},
			want: "linux/arm64",
		},
		{
			name: "UI меняет на darwin/amd64",
			set: func(t *testing.T) {
				code, body := e.setPlatformUI(c, "manual", "1.0.0", "darwin", "amd64")
				if code != http.StatusSeeOther {
					t.Fatalf("POST платформы в UI: status = %d, want 303; body: %s", code, firstLines(body))
				}
			},
			want: "darwin/amd64",
		},
		{
			name: "UI сбрасывает в unknown пустым значением",
			set: func(t *testing.T) {
				code, body := e.setPlatformUI(c, "manual", "1.0.0", "", "")
				if code != http.StatusSeeOther {
					t.Fatalf("сброс в UI: status = %d, want 303; body: %s", code, firstLines(body))
				}
			},
			want: "",
		},
		{
			name: "API ставит any",
			set: func(t *testing.T) {
				code, body := e.patchPlatform("manual", "1.0.0", `{"platform":"any"}`)
				if code != http.StatusOK {
					t.Fatalf("PATCH any: status = %d, want 200; body: %s", code, body)
				}
			},
			want: "any",
		},
		{
			name: "API сбрасывает пустой строкой",
			set: func(t *testing.T) {
				code, body := e.patchPlatform("manual", "1.0.0", `{"platform":""}`)
				if code != http.StatusOK {
					t.Fatalf("PATCH пустой строкой: status = %d, want 200; body: %s", code, body)
				}
				if !strings.Contains(body, `"platform":""`) {
					t.Errorf("сброс не отражён в ответе; body: %s", body)
				}
			},
			want: "",
		},
		{
			name: "API канонизирует регистр и края",
			set: func(t *testing.T) {
				code, body := e.patchPlatform("manual", "1.0.0", `{"platform":"  Linux/AMD64 "}`)
				if code != http.StatusOK {
					t.Fatalf("PATCH: status = %d, want 200; body: %s", code, body)
				}
			},
			want: "linux/amd64",
		},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			s.set(t)
			e.wantPlatformEverywhere(c, "manual", "1.0.0", s.want, s.name)
		})
	}
}

// TestManualPlatformRefusals: PATCH без поля ничего не меняет, мусор — 400
// invalid_platform без записи, чужие адреса — 404, тело не-JSON — 415.
func TestManualPlatformRefusals(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("refuse")
	e.seed("refuse", "1.0.0")
	if code, body := e.patchPlatform("refuse", "1.0.0", `{"platform":"linux/amd64"}`); code != http.StatusOK {
		t.Fatalf("подготовка: status = %d; body: %s", code, body)
	}

	t.Run("тело без поля ничего не меняет", func(t *testing.T) {
		code, body := e.patchPlatform("refuse", "1.0.0", `{}`)
		if code != http.StatusOK {
			t.Fatalf("PATCH {}: status = %d, want 200; body: %s", code, body)
		}
		e.wantPlatformEverywhere(c, "refuse", "1.0.0", "linux/amd64", "PATCH без поля platform")
	})

	t.Run("мусор — 400 и прежнее значение", func(t *testing.T) {
		for _, bad := range []string{`{"platform":"amd64"}`, `{"platform":"linux/"}`,
			`{"platform":"plan9/amd64"}`, `{"platform":"linux/amd64/v3"}`} {
			code, body := e.patchPlatform("refuse", "1.0.0", bad)
			if code != http.StatusBadRequest {
				t.Errorf("PATCH %s: status = %d, want 400; body: %s", bad, code, body)
				continue
			}
			if !strings.Contains(body, `"invalid_platform"`) {
				t.Errorf("PATCH %s: код ошибки не invalid_platform; body: %s", bad, body)
			}
		}
		e.wantPlatformEverywhere(c, "refuse", "1.0.0", "linux/amd64", "после отказов платформа не менялась")
	})

	t.Run("несуществующая версия и приложение — 404", func(t *testing.T) {
		if code, _ := e.patchPlatform("refuse", "9.9.9", `{"platform":"any"}`); code != http.StatusNotFound {
			t.Errorf("PATCH несуществующей версии: status = %d, want 404", code)
		}
		if code, _ := e.patchPlatform("nosuchapp", "1.0.0", `{"platform":"any"}`); code != http.StatusNotFound {
			t.Errorf("PATCH в несуществующем приложении: status = %d, want 404", code)
		}
	})

	t.Run("несуществующие адреса в UI — 404, а не 500", func(t *testing.T) {
		for _, path := range []string{
			"/apps/refuse/versions/9.9.9/platform",
			"/apps/nosuchapp/versions/1.0.0/platform",
		} {
			code, body := e.uiPostStatus(c, path,
				url.Values{"platform_os": {"any"}, "platform_arch": {""}})
			if code != http.StatusNotFound {
				t.Errorf("POST %s: status = %d, want 404; body: %s", path, code, firstLines(body))
			}
		}
	})

	t.Run("тело без application/json — 415", func(t *testing.T) {
		code, body := e.statusAs(adminCred, "PATCH", "/api/apps/refuse/versions/1.0.0",
			strings.NewReader(`{"platform":"any"}`), map[string]string{"Content-Type": "text/plain"})
		if code != http.StatusUnsupportedMediaType {
			t.Errorf("PATCH с text/plain: status = %d, want 415; body: %s", code, body)
		}
		e.wantPlatformEverywhere(c, "refuse", "1.0.0", "linux/amd64", "после 415 платформа не менялась")
	})

	t.Run("негодная пара в UI — 400 с открытой модалкой строки", func(t *testing.T) {
		code, body := e.setPlatformUI(c, "refuse", "1.0.0", "linux", "")
		if code != http.StatusBadRequest {
			t.Fatalf("половина пары в UI: status = %d, want 400; body: %s", code, firstLines(body))
		}
		if !strings.Contains(body, `id="plat-1.0.0" open`) {
			t.Errorf("модалка строки не отрендерена открытой; body: %s", firstLines(body))
		}
		e.wantPlatformEverywhere(c, "refuse", "1.0.0", "linux/amd64", "после отказа UI платформа не менялась")
	})

	t.Run("UI без CSRF — 403 и платформа не меняется", func(t *testing.T) {
		resp := e.uiPost(c, "/apps/refuse/versions/1.0.0/platform",
			url.Values{"platform_os": {"windows"}, "platform_arch": {"amd64"}})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST без csrf_token: status = %d, want 403", resp.StatusCode)
		}
		e.wantPlatformEverywhere(c, "refuse", "1.0.0", "linux/amd64", "после отказа по CSRF")
	})
}

// TestPlatformDialogPrefilledWithCurrentValue: модалка строки подставляет
// текущее значение в оба списка — иначе «поправить архитектуру» превращается в
// «выбрать заново обе половины», а промах молча перезаписывает ОС.
func TestPlatformDialogPrefilledWithCurrentValue(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("prefill")
	e.seed("prefill", "1.0.0")
	if code, body := e.patchPlatform("prefill", "1.0.0", `{"platform":"windows/386"}`); code != http.StatusOK {
		t.Fatalf("подготовка: status = %d; body: %s", code, body)
	}

	row := e.versionRowHTML(c, "prefill", "1.0.0")
	for _, want := range []string{`value="windows" selected`, `value="386" selected`} {
		if !strings.Contains(row, want) {
			t.Errorf("в модалке строки нет %q — текущее значение не подставлено; строка: %s", want, firstLines(row))
		}
	}
}

// TestNewPlatformRoutesFollowRoleMatrix: deployer не может проставить платформу
// ни через API, ни через UI; developer и старше — могут. Право то же, что у
// заливки версии (PermVersion), матрица живёт в auth и второй копии не имеет.
func TestNewPlatformRoutesFollowRoleMatrix(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("roles8")
	e.seed("roles8", "1.0.0")

	t.Run("deployer_не_может", func(t *testing.T) {
		cr := e.mkUser("r8-deployer", validPass, "deployer")
		code, body := e.statusAs(cr, "PATCH", "/api/apps/roles8/versions/1.0.0",
			strings.NewReader(`{"platform":"linux/amd64"}`), jsonHdr)
		if !deniedAPI(t, code, body) {
			t.Errorf("PATCH версии для deployer: status = %d, want 403; body: %s", code, body)
		}
		// В UI ему закрыт вход целиком (нет PermUI) — отказ обязан прийти
		// страницей роли, а не 404 и не успехом.
		c := e.mustLoginAs(cr)
		code, body = e.setPlatformUI(c, "roles8", "1.0.0", "linux", "amd64")
		if !deniedUI(t, code, body) {
			t.Errorf("POST платформы в UI для deployer: status = %d, want 403", code)
		}
		e.wantPlatformEverywhere(nil, "roles8", "1.0.0", testPlatform, "deployer ничего не изменил")
	})

	for _, role := range []string{"developer", "maintainer", "admin"} {
		t.Run(role+"_может", func(t *testing.T) {
			cr := e.mkUser("r8-"+role, validPass, role)
			code, body := e.statusAs(cr, "PATCH", "/api/apps/roles8/versions/1.0.0",
				strings.NewReader(`{"platform":"linux/amd64"}`), jsonHdr)
			if code != http.StatusOK {
				t.Fatalf("PATCH версии для %s: status = %d, want 200; body: %s", role, code, body)
			}
			c := e.mustLoginAs(cr)
			code, body = e.setPlatformUI(c, "roles8", "1.0.0", "any", "")
			if code != http.StatusSeeOther {
				t.Fatalf("POST платформы в UI для %s: status = %d, want 303; body: %s", role, code, firstLines(body))
			}
			e.wantPlatformEverywhere(c, "roles8", "1.0.0", "any", role+" проставил платформу")
		})
	}
}
