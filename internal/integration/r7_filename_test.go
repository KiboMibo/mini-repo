package integration

// T23: ?filename= обязателен для PUT /api/apps/{name}/versions/{version}.
// Ломающее изменение — прежний молчаливый дефолт «{app}-{version}» убран,
// потому что отдавал многофайловый релиз файлом без расширения.
// Задача R7-test.
//
// Unit-тест api_t23_test.go проверяет коды и текст на голом mux; здесь тот же
// контракт проверяется сквозь всё приложение и с обязательной добавкой,
// которой на уровне mux не видно: после каждого отказа на диске и в БД пусто.

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPutVersionFilenameIsMandatory перебирает все формы «имени нет» и «имя
// негодное». В каждом случае — отказ, отсутствие версии в БД, отсутствие
// каталога версии и отсутствие остатков в .tmp.
func TestPutVersionFilenameIsMandatory(t *testing.T) {
	cases := []struct {
		name    string // имя подтеста и версия, на которую льём
		version string
		query   string
		code    string // ожидаемый контрактный код ошибки
		why     string
	}{
		{
			name: "no_parameter", version: "1.0.0", query: "",
			code: "filename_required",
			why:  "параметра нет вовсе — клиент, живший на дефолте до T23",
		},
		{
			name: "empty_parameter", version: "1.1.0", query: "?filename=",
			code: "filename_required",
			why:  "параметр есть, значение пустое",
		},
		{
			name: "whitespace_only", version: "1.2.0", query: "?filename=%20%20%20",
			code: "filename_required",
			why:  "значение из одних пробелов — то же «пусто», записанное иначе",
		},
		{
			name: "parent_traversal", version: "1.3.0", query: "?filename=" + url.QueryEscape("../x"),
			code: "invalid_filename",
			why:  "выход из каталога версии",
		},
		{
			name: "nested_path", version: "1.4.0", query: "?filename=" + url.QueryEscape("a/b"),
			code: "invalid_filename",
			why:  "разделитель пути внутри имени",
		},
		{
			name: "dot_dot", version: "1.5.0", query: "?filename=..",
			code: "invalid_filename",
			why:  "«..» — не имя файла",
		},
		{
			name: "backslash_path", version: "1.6.0", query: "?filename=" + url.QueryEscape(`a\b`),
			code: "invalid_filename",
			why:  "разделитель пути Windows",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, defaultMaxUpload)
			e.createApp("myapp")
			payload := tarGzBytes(t, multiFileRelease())

			resp := e.putVersionRaw("myapp", tc.version, tc.query, payload, "")
			wantJSONError(t, resp, http.StatusBadRequest, tc.code)
			e.wantNoVersion("myapp", tc.version, tc.why)

			// Отказ ничего не публикует и в списке версий: даже пустой каталог
			// приложения не должен обзавестись содержимым.
			if got := e.versionNamesOf("myapp"); len(got) != 0 {
				t.Errorf("%s: после отказа у приложения появились версии %v", tc.why, got)
			}
		})
	}
}

// TestPutVersionValidFilenameIsCreated: обратная сторона той же проверки —
// годное имя по-прежнему даёт 201 и кладёт файл ровно под этим именем.
// Без неё вся матрица выше зеленела бы и на хендлере, отвергающем всё подряд.
func TestPutVersionValidFilenameIsCreated(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	payload := tarGzBytes(t, multiFileRelease())
	const name = "myapp-1.0.0.tar.gz"

	obj := e.mustPutVersion("myapp", "1.0.0", "?filename="+name, payload, sha256hex(payload))
	if obj["filename"] != name {
		t.Errorf("filename = %v, want %q", obj["filename"], name)
	}
	mustExist(t, filepath.Join(e.versionDir("myapp", "1.0.0"), name), "файл версии")
	e.wantNoTmpLeftovers("после успешной загрузки")
	e.assertNoDanglingRows()
}

// TestPutVersionFilenameWithSpacesInside: пробел ВНУТРИ имени — не то же, что
// имя из одних пробелов: «my app-1.0.0.tar.gz» законное имя файла, и отвергать
// его не за что. Тест держит границу с обеих сторон, чтобы починка пробельного
// случая не выродилась в запрет пробелов вообще.
func TestPutVersionFilenameWithSpacesInside(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	payload := tarGzBytes(t, multiFileRelease())
	const name = "my app 1.0.0.tar.gz"

	obj := e.mustPutVersion("myapp", "1.0.0", "?filename="+url.QueryEscape(name), payload, "")
	if obj["filename"] != name {
		t.Errorf("filename = %v, want %q", obj["filename"], name)
	}
	_, hdr, got := e.downloadFull("myapp", "1.0.0")
	wantDispositionName(t, hdr, name)
	wantSameEntries(t, unTarGz(t, got), multiFileRelease(), "архив с пробелами в имени")
}

// TestLegacyVersionsKeepTheirOldNames: версии, залитые ДО T23, продолжают
// скачиваться под своими прежними именами — теми самыми «{app}-{version}» без
// расширения. Ломающим изменением был контракт загрузки, а не хранилище;
// строка создаётся напрямую через store, минуя API, ровно так, как она лежит
// в боевой БД со времён дефолта.
func TestLegacyVersionsKeepTheirOldNames(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	a, err := e.st.GetApp("myapp")
	if err != nil || a == nil {
		t.Fatalf("GetApp: %v %v", a, err)
	}

	// Так выглядела запись до T23: имя без расширения, хотя внутри — архив.
	legacyName := defaultFileName("myapp", "0.9.0")
	for _, ext := range []string{".tar.gz", ".zip", ".tgz"} {
		if strings.HasSuffix(legacyName, ext) {
			t.Fatalf("фикстура сломана: старое имя %q не должно нести расширения архива", legacyName)
		}
	}
	content := tarGzBytes(t, multiFileRelease())

	dir := e.versionDir("myapp", "0.9.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyName), content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := e.st.CreateVersion(a.ID, "0.9.0", legacyName, int64(len(content)), sha256hex(content)); err != nil {
		t.Fatalf("CreateVersion (старая строка): %v", err)
	}

	status, hdr, got := e.downloadFull("myapp", "0.9.0")
	if status != http.StatusOK {
		t.Fatalf("GET /download/myapp/0.9.0: status = %d, want 200", status)
	}
	if len(got) != len(content) || sha256hex(got) != sha256hex(content) {
		t.Errorf("старая версия скачалась порченой: %d байт, sha %s", len(got), sha256hex(got))
	}
	// Главное обещание совместимости: имя не переписано задним числом.
	wantDispositionName(t, hdr, legacyName)
	if h := hdr.Get("X-Checksum-Sha256"); h != sha256hex(content) {
		t.Errorf("X-Checksum-Sha256 = %s, want %s", h, sha256hex(content))
	}

	// И в списке версий она видна под своим прежним именем.
	resp := e.api("GET", "/api/apps/myapp/versions/0.9.0", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET версии: status = %d, want 200", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["filename"]; got != legacyName {
		t.Errorf("filename в API = %v, want %q", got, legacyName)
	}

	// Новая версия того же приложения уже обязана нести расширение — старое и
	// новое сосуществуют.
	e.mustPutVersion("myapp", "1.0.0", "?filename=myapp-1.0.0.tar.gz", content, sha256hex(content))
	e.assertNoDanglingRows()
}

// TestLegacyDownloadUnaffectedByNewRefusals: отказ новой загрузки не задевает
// уже лежащие версии — ни строку, ни файл.
func TestLegacyDownloadUnaffectedByNewRefusals(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	content := tarGzBytes(t, multiFileRelease())
	e.mustPutVersion("myapp", "1.0.0", "?filename=myapp-1.0.0.tar.gz", content, "")

	// Несколько отказов подряд по разным причинам. Пробельного имени здесь
	// нарочно нет: оно принимается (находка R7-F1) и живёт отдельным подтестом
	// в TestPutVersionFilenameIsMandatory — одна находка, один красный тест.
	for _, q := range []string{"", "?filename=", "?filename=" + url.QueryEscape("../x"), "?filename=.."} {
		resp := e.putVersionRaw("myapp", "2.0.0", q, content, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT с query %q: status = %d, want 400", q, resp.StatusCode)
		}
	}

	_, hdr, got := e.downloadFull("myapp", "1.0.0")
	if sha256hex(got) != sha256hex(content) {
		t.Error("существующая версия испорчена отказанными загрузками")
	}
	wantDispositionName(t, hdr, "myapp-1.0.0.tar.gz")
	e.wantNoVersion("myapp", "2.0.0", "после серии отказов")
	e.assertNoDanglingRows()
}
