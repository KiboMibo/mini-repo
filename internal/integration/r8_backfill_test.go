package integration

// Обновление боевой установки до волны 8. Критерий «обновление на сервере не
// сломает прод» проверяется так же, как в R6, но честнее: установка набивается
// НАСТОЯЩИМ предыдущим бинарником (`git archive` merge-base с develop →
// `go build` → `serve`), а не рукописной схемой. Потом на том же каталоге
// поднимается текущий код, и проверяется всё сразу: колонка досоздана, backfill
// проставил платформу бинарнику, архив остался без платформы, данные целы,
// повторный старт ничего не портит и не дублирует.
// Задача R8-test.

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"
)

const (
	legacy8App     = "legacy8"
	legacy8BinVer  = "1.0.0"
	legacy8ArchVer = "1.1.0"
	legacy8BinFile = "legacy8-bin"
	legacy8ArchFn  = "legacy8-1.1.0.tar.gz"
)

// legacy8Target нарочно НЕ хостовая платформа: если бы backfill (или
// определение) подставлял `runtime.GOOS/GOARCH` вместо чтения файла, на
// хостовом бинарнике тест бы этого не заметил.
var legacy8Target = target{"linux", "arm64"}

func TestUpgradeOfPreWave8Installation(t *testing.T) {
	skipIfShort(t, "сборка предыдущего бинарника и кросс-сборка подопытного")

	root := t.TempDir()
	cfg := cfgAt(root, r8MaxUpload)
	bin := crossBuild(t, legacy8Target)
	archive := tarGzBytes(t, multiFileRelease())

	inst := seedPreWave8Install(t, cfg.DataDir, legacy8App, "built before wave 8", []legacyUpload{
		{legacy8BinVer, legacy8BinFile, bin},
		{legacy8ArchVer, legacy8ArchFn, archive},
	})

	// Два прогона на одном каталоге: обновление и обычный перезапуск уже
	// обновлённой установки. Backfill обязан быть идемпотентным.
	for _, pass := range []string{"после обновления", "после перезапуска"} {
		t.Run(pass, func(t *testing.T) {
			e := bootEnv(t, cfg)

			t.Run("бинарнику_проставлена_платформа", func(t *testing.T) {
				if got := e.platformAs(inst.cred, legacy8App, legacy8BinVer); got != legacy8Target.String() {
					t.Errorf("платформа старого бинарника = %q, want %q (backfill не сработал)",
						got, legacy8Target)
				}
			})

			t.Run("у_архива_платформа_осталась_пустой", func(t *testing.T) {
				if got := e.platformAs(inst.cred, legacy8App, legacy8ArchVer); got != "" {
					t.Errorf("платформа архива = %q, want \"\" — угадывать её нельзя", got)
				}
			})

			t.Run("данные_целы", func(t *testing.T) {
				code, body := e.statusAs(inst.cred, "GET", "/api/apps/"+legacy8App, nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET приложения: status = %d, want 200; body: %s", code, body)
				}
				if !strings.Contains(body, "built before wave 8") {
					t.Errorf("описание приложения потеряно; body: %s", body)
				}
				for _, tc := range []struct {
					version string
					want    []byte
				}{{legacy8BinVer, bin}, {legacy8ArchVer, archive}} {
					got := e.downloadAs(inst.cred, legacy8App, tc.version)
					if !bytes.Equal(got, tc.want) {
						t.Errorf("файл версии %s изменился: скачано %d байт, залито %d",
							tc.version, len(got), len(tc.want))
					}
					if h := sha256hex(got); h != sha256hex(tc.want) {
						t.Errorf("sha256 версии %s = %s, want %s", tc.version, h, sha256hex(tc.want))
					}
				}
			})

			t.Run("старый_пароль_всё_ещё_пускает", func(t *testing.T) {
				code, body := e.statusAs(inst.cred, "GET", "/api/me", nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET /api/me: status = %d, want 200; body: %s", code, body)
				}
			})

			t.Run("версии_не_задвоились", func(t *testing.T) {
				code, body := e.statusAs(inst.cred, "GET", "/api/apps/"+legacy8App+"/versions", nil, nil)
				if code != http.StatusOK {
					t.Fatalf("GET списка версий: status = %d; body: %s", code, body)
				}
				if n := strings.Count(body, `"version":`); n != 2 {
					t.Errorf("версий в списке %d, want 2 (backfill не должен создавать строк); body: %s", n, body)
				}
			})
		})
	}

	// Третий прогон — тот же каталог после ручной простановки: значение,
	// поставленное человеком, перезапуск трогать не вправе.
	t.Run("ручная_платформа_переживает_перезапуск", func(t *testing.T) {
		e := bootEnv(t, cfg)
		code, body := e.statusAs(inst.cred, "PATCH",
			"/api/apps/"+legacy8App+"/versions/"+legacy8ArchVer,
			strings.NewReader(`{"platform":"any"}`), jsonHdr)
		if code != http.StatusOK {
			t.Fatalf("PATCH архива: status = %d, want 200; body: %s", code, body)
		}

		e2 := bootEnv(t, cfg)
		if got := e2.platformAs(inst.cred, legacy8App, legacy8ArchVer); got != "any" {
			t.Errorf("после перезапуска платформа архива = %q, want any", got)
		}
	})

	// Обратная сторона того же правила: платформа, СБРОШЕННАЯ человеком в
	// «неизвестно», при следующем старте определяется заново — backfill берёт
	// все пустые строки и отличить «ещё не смотрели» от «сбросили нарочно» не
	// может. Поведение осознанное (T24), но заметное, и тест фиксирует его,
	// чтобы изменение не прошло молча.
	t.Run("сброшенная_платформа_определяется_заново", func(t *testing.T) {
		e := bootEnv(t, cfg)
		code, body := e.statusAs(inst.cred, "PATCH",
			"/api/apps/"+legacy8App+"/versions/"+legacy8BinVer,
			strings.NewReader(`{"platform":""}`), jsonHdr)
		if code != http.StatusOK {
			t.Fatalf("сброс платформы бинарника: status = %d; body: %s", code, body)
		}
		if got := e.platformAs(inst.cred, legacy8App, legacy8BinVer); got != "" {
			t.Fatalf("сброс не применился: платформа = %q", got)
		}

		e2 := bootEnv(t, cfg)
		if got := e2.platformAs(inst.cred, legacy8App, legacy8BinVer); got != legacy8Target.String() {
			t.Errorf("после перезапуска платформа = %q, want %q (backfill определяет пустые заново)",
				got, legacy8Target)
		}
	})
}

// TestBackfillSurvivesMissingFile: файл версии удалён из-под сервиса (чистка
// диска, недокачанный бэкап). Backfill обязан пропустить такую строку и не
// уронить старт — иначе один потерянный файл делает установку неподнимаемой.
func TestBackfillSurvivesMissingFile(t *testing.T) {
	// Установка волны 8: версия есть, платформа пустая, файла нет.
	e := newEnv(t, defaultMaxUpload)
	e.createApp("gone")
	e.seed("gone", "1.0.0")
	if code, body := e.patchPlatform("gone", "1.0.0", `{"platform":""}`); code != http.StatusOK {
		t.Fatalf("сброс платформы: status = %d; body: %s", code, body)
	}
	if err := os.RemoveAll(e.versionDir("gone", "1.0.0")); err != nil {
		t.Fatalf("удаление каталога версии: %v", err)
	}

	// Перезапуск на том же каталоге: старт проходит, строка на месте.
	e2 := bootEnv(t, e.cfg)
	code, body := e2.statusAs(adminCred, "GET", "/api/apps/gone/versions/1.0.0", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("версия с потерянным файлом после перезапуска: status = %d, want 200; body: %s", code, body)
	}
	if !strings.Contains(body, `"platform":""`) {
		t.Errorf("платформа версии без файла = не пусто; body: %s", body)
	}
}
