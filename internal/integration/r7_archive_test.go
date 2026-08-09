package integration

// Многофайловые релизы: то, ради чего затевалась волна 7. До неё в проекте не
// было ни одного теста на архив — все загрузки были плоским «binary-of:...»,
// то есть ровно тем случаем, на котором дефолтное имя без расширения не жало.
// Задача R7-test.

import (
	"bytes"
	"mime"
	"net/http"
	"strings"
	"testing"
)

// TestTarGzReleaseRoundTripViaAPI: настоящий .tar.gz с вложенными каталогами
// заливается через API, скачивается обратно и распаковывается. Проверяются все
// звенья цепочки сразу — байты, дайджест, имя, тип и содержимое: порча на любом
// из них делает релиз непригодным, а по одному только 201 этого не видно.
func TestTarGzReleaseRoundTripViaAPI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	entries := multiFileRelease()
	archive := tarGzBytes(t, entries)
	const name = "myapp-1.0.0.tar.gz"
	sum := sha256hex(archive)

	obj := e.mustPutVersion("myapp", "1.0.0", "?filename="+name, archive, sum)
	if obj["filename"] != name {
		t.Errorf("filename в ответе = %v, want %q", obj["filename"], name)
	}
	if obj["sha256"] != sum {
		t.Errorf("sha256 в ответе = %v, want %s", obj["sha256"], sum)
	}
	if obj["size_bytes"] != float64(len(archive)) {
		t.Errorf("size_bytes = %v, want %d", obj["size_bytes"], len(archive))
	}

	status, hdr, got := e.downloadFull("myapp", "1.0.0")
	if status != http.StatusOK {
		t.Fatalf("GET /download/myapp/1.0.0: status = %d, want 200", status)
	}
	if !bytes.Equal(got, archive) {
		t.Errorf("скачано %d байт, залито %d — тела не совпадают", len(got), len(archive))
	}
	if h := sha256hex(got); h != sum {
		t.Errorf("sha256 скачанного = %s, want %s", h, sum)
	}
	if h := hdr.Get("X-Checksum-Sha256"); h != sum {
		t.Errorf("X-Checksum-Sha256 = %s, want %s", h, sum)
	}
	wantDispositionName(t, hdr, name)
	wantContentType(t, hdr, gzipTypes, "скачанный .tar.gz")
	wantSameEntries(t, unTarGz(t, got), entries, "распаковка скачанного .tar.gz")
}

// TestZipReleaseRoundTripViaAPI: то же самое для .zip — второй формат, который
// пользователи приносят, и второе расширение, по которому определяется тип.
func TestZipReleaseRoundTripViaAPI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	entries := multiFileRelease()
	archive := zipBytes(t, entries)
	const name = "myapp-2.0.0.zip"
	sum := sha256hex(archive)

	e.mustPutVersion("myapp", "2.0.0", "?filename="+name, archive, sum)

	status, hdr, got := e.downloadFull("myapp", "2.0.0")
	if status != http.StatusOK {
		t.Fatalf("GET /download/myapp/2.0.0: status = %d, want 200", status)
	}
	if !bytes.Equal(got, archive) {
		t.Errorf("скачано %d байт, залито %d — тела не совпадают", len(got), len(archive))
	}
	if h := sha256hex(got); h != sum {
		t.Errorf("sha256 скачанного = %s, want %s", h, sum)
	}
	wantDispositionName(t, hdr, name)
	wantContentType(t, hdr, zipTypes, "скачанный .zip")
	wantSameEntries(t, unZip(t, got), entries, "распаковка скачанного .zip")
}

// TestTarGzReleaseRoundTripViaUIForm: тот же архив, но залитый обычной
// multipart-формой — путём, которым ходит браузер без JS и которым, теми же
// байтами, ходит XHR из T22. Имя файла в UI берётся из части формы, а не из
// ?filename=, поэтому расширение обязано доехать оттуда.
func TestTarGzReleaseRoundTripViaUIForm(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	// CSRF-кука выдаётся на странице; страница приложения нужна и сама по себе.
	e.uiPageBody(c, "/apps/myapp", http.StatusOK)

	entries := multiFileRelease()
	archive := tarGzBytes(t, entries)
	const name = "myapp-3.0.0.tar.gz"
	sum := sha256hex(archive)

	resp := e.uploadUI(c, "myapp", "3.0.0", sum, name, archive, e.csrfOf(c))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /apps/myapp/versions: status = %d, want 303; body: %s",
			resp.StatusCode, readBody(t, resp))
	}

	status, hdr, got := e.downloadFull("myapp", "3.0.0")
	if status != http.StatusOK {
		t.Fatalf("GET /download/myapp/3.0.0: status = %d, want 200", status)
	}
	if !bytes.Equal(got, archive) {
		t.Errorf("скачано %d байт, залито %d — тела не совпадают", len(got), len(archive))
	}
	if h := sha256hex(got); h != sum {
		t.Errorf("sha256 скачанного = %s, want %s", h, sum)
	}
	wantDispositionName(t, hdr, name)
	wantContentType(t, hdr, gzipTypes, "скачанный через UI .tar.gz")
	wantSameEntries(t, unTarGz(t, got), entries, "распаковка залитого через UI архива")
}

// TestZipReleaseRoundTripViaUIForm: .zip через ту же форму.
func TestZipReleaseRoundTripViaUIForm(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")
	c := e.uiClient()
	e.login(c, "/")
	e.uiPageBody(c, "/apps/myapp", http.StatusOK)

	entries := multiFileRelease()
	archive := zipBytes(t, entries)
	const name = "myapp-4.0.0.zip"

	resp := e.uploadUI(c, "myapp", "4.0.0", sha256hex(archive), name, archive, e.csrfOf(c))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST upload: status = %d, want 303; body: %s", resp.StatusCode, readBody(t, resp))
	}

	_, hdr, got := e.downloadFull("myapp", "4.0.0")
	if !bytes.Equal(got, archive) {
		t.Errorf("тела не совпадают: скачано %d байт, залито %d", len(got), len(archive))
	}
	wantDispositionName(t, hdr, name)
	wantContentType(t, hdr, zipTypes, "скачанный через UI .zip")
	wantSameEntries(t, unZip(t, got), entries, "распаковка залитого через UI .zip")
}

// TestContentTypeComesFromExtensionNotContent: тип берётся из РАСШИРЕНИЯ имени,
// а не угадывается по содержимому.
//
// Отдельный тест понадобился после проверки чувствительности: на настоящем
// архиве оба механизма дают один ответ (у gzip и zip узнаваемая сигнатура), и
// тест на .tar.gz остаётся зелёным, даже если имя файла из отдачи убрать вовсе.
// Различает их только расхождение: содержимое — обычный текст, имя — архивное.
// Расширение решает → тип архивный; решает содержимое → text/plain.
//
// Расширения .zip/.gz нет во встроенной таблице Go — она читается из системной
// (/etc/mime.types), поэтому в голом образе без неё различить механизмы нечем;
// тогда тест честно объявляет об этом через Skip, а не зеленеет вхолостую.
func TestContentTypeComesFromExtensionNotContent(t *testing.T) {
	want := mime.TypeByExtension(".zip")
	if want == "" {
		t.Skip("в системной таблице MIME нет .zip — механизм не различим в этом окружении")
	}
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	// Содержимое — заведомо не архив: по сигнатуре это text/plain.
	notAnArchive := []byte(strings.Repeat("this is plain ASCII text, not a zip archive\n", 16))
	e.mustPutVersion("myapp", "1.0.0", "?filename=myapp-1.0.0.zip", notAnArchive, sha256hex(notAnArchive))

	_, hdr, got := e.downloadFull("myapp", "1.0.0")
	if !bytes.Equal(got, notAnArchive) {
		t.Errorf("тело изменилось при отдаче")
	}
	ct := hdr.Get("Content-Type")
	base := strings.TrimSpace(strings.Split(ct, ";")[0])
	if strings.HasPrefix(base, "text/") {
		t.Errorf("Content-Type = %q — определён по содержимому, а не по расширению .zip", ct)
	}
	if base != strings.TrimSpace(strings.Split(want, ";")[0]) {
		t.Errorf("Content-Type = %q, want %q (по расширению .zip)", ct, want)
	}
}

// TestArchiveDownloadedByLatestKeepsName: скачивание по псевдо-версии latest
// отдаёт тот же архив под тем же именем. Отдельный тест, потому что ветка
// latest в download достаёт строку иначе и легко теряет имя файла.
func TestArchiveDownloadedByLatestKeepsName(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	entries := multiFileRelease()
	archive := tarGzBytes(t, entries)
	const name = "myapp-5.0.0.tar.gz"
	e.mustPutVersion("myapp", "5.0.0", "?filename="+name, archive, sha256hex(archive))

	status, hdr, got := e.downloadFull("myapp", "latest")
	if status != http.StatusOK {
		t.Fatalf("GET /download/myapp/latest: status = %d, want 200", status)
	}
	if !bytes.Equal(got, archive) {
		t.Errorf("latest отдал не тот архив: %d байт против %d", len(got), len(archive))
	}
	wantDispositionName(t, hdr, name)
	wantContentType(t, hdr, gzipTypes, "latest .tar.gz")
	wantSameEntries(t, unTarGz(t, got), entries, "распаковка latest")
}

// TestArchiveSurvivesAppRename: релиз, залитый архивом, после переименования
// приложения скачивается под прежним именем файла. Инвариант волны 5, но на
// архиве он проверяется впервые — а именно на нём цена потери имени наибольшая.
func TestArchiveSurvivesAppRename(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("myapp")

	entries := multiFileRelease()
	archive := tarGzBytes(t, entries)
	const name = "myapp-6.0.0.tar.gz"
	e.mustPutVersion("myapp", "6.0.0", "?filename="+name, archive, sha256hex(archive))

	body, err := jsonBody(map[string]string{"name": "renamed"})
	if err != nil {
		t.Fatal(err)
	}
	resp := e.api("PATCH", "/api/apps/myapp", bytes.NewReader([]byte(body)), jsonHdr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH rename: status = %d, want 200", resp.StatusCode)
	}

	status, hdr, got := e.downloadFull("renamed", "6.0.0")
	if status != http.StatusOK {
		t.Fatalf("GET /download/renamed/6.0.0: status = %d, want 200", status)
	}
	if !bytes.Equal(got, archive) {
		t.Error("после переименования отдан не тот архив")
	}
	// Имя файла принадлежит версии, а не приложению: оно не следует за rename.
	wantDispositionName(t, hdr, name)
	wantSameEntries(t, unTarGz(t, got), entries, "распаковка после переименования")
}
