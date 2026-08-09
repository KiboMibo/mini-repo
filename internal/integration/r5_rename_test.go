package integration

// Сквозные сценарии переименования приложения (волна 5: T12 store+files,
// T13 JSON API, T14 веб-UI). Каждый тест поднимает полное приложение через
// app.New + httptest и проверяет обе стороны — API и UI — плюс диск.

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// renameViaAPI отправляет PATCH /api/apps/{name} и возвращает ответ.
func (e *env) renameViaAPI(name, body string) *http.Response {
	e.t.Helper()
	return e.api("PATCH", "/api/apps/"+name, strings.NewReader(body), jsonHdr)
}

// renameViaUI отправляет POST /apps/{name}/edit с CSRF-токеном клиента.
func (e *env) renameViaUI(c *http.Client, name, newName, desc string) *http.Response {
	e.t.Helper()
	return e.uiPost(c, "/apps/"+name+"/edit", url.Values{
		"csrf_token":  {e.csrfOf(c)},
		"name":        {newName},
		"description": {desc},
	})
}

// TestRenameViaAPIIsVisibleEverywhere: переименование через API видно и в API,
// и в UI; скачивание по новому имени отдаёт байт-в-байт залитое, по старому —
// 404; каталог на диске переехал целиком.
func TestRenameViaAPIIsVisibleEverywhere(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("oldname")
	v1 := e.seed("oldname", "1.0.0")
	v2 := e.seed("oldname", "2.3.4")

	resp := e.renameViaAPI("oldname", `{"name":"newname"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH rename: status = %d, want 200; body: %s", resp.StatusCode, readBody(t, resp))
	}
	m := decodeJSON(t, resp)
	if m["name"] != "newname" {
		t.Errorf("PATCH response name = %v, want %q", m["name"], "newname")
	}

	t.Run("api_sees_new_name_only", func(t *testing.T) {
		if status, _ := e.appJSONOf("newname"); status != http.StatusOK {
			t.Errorf("GET /api/apps/newname: status = %d, want 200", status)
		}
		if status, _ := e.appJSONOf("oldname"); status != http.StatusNotFound {
			t.Errorf("GET /api/apps/oldname: status = %d, want 404", status)
		}
		if got := e.versionNamesOf("newname"); len(got) != 2 {
			t.Errorf("versions after rename = %v, want 2 entries", got)
		}
	})

	t.Run("ui_sees_new_name_only", func(t *testing.T) {
		body := e.uiPageBody(c, "/apps/newname", http.StatusOK)
		if !strings.Contains(body, "newname") {
			t.Errorf("UI app page does not mention the new name")
		}
		resp := e.uiGet(c, "/apps/oldname")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("UI GET /apps/oldname: status = %d, want 404", resp.StatusCode)
		}
		index := e.uiPageBody(c, "/", http.StatusOK)
		if !strings.Contains(index, "newname") {
			t.Errorf("index page does not list newname")
		}
		if strings.Contains(index, ">oldname<") {
			t.Errorf("index page still lists oldname")
		}
	})

	t.Run("download_by_new_name_is_byte_identical", func(t *testing.T) {
		if got := e.mustDownload("newname", "1.0.0"); !bytes.Equal(got, v1) {
			t.Errorf("1.0.0 after rename: %d bytes, want the %d uploaded bytes", len(got), len(v1))
		}
		if got := e.mustDownload("newname", "2.3.4"); !bytes.Equal(got, v2) {
			t.Errorf("2.3.4 after rename: %d bytes, want the %d uploaded bytes", len(got), len(v2))
		}
		if got := e.mustDownload("newname", "latest"); !bytes.Equal(got, v2) {
			t.Errorf("latest after rename did not resolve to 2.3.4")
		}
	})

	t.Run("download_by_old_name_is_404", func(t *testing.T) {
		e.wantDownloadStatus("oldname", "1.0.0", http.StatusNotFound)
		e.wantDownloadStatus("oldname", "latest", http.StatusNotFound)
	})

	t.Run("directory_moved_and_old_one_is_gone", func(t *testing.T) {
		mustNotExist(t, e.appDir("oldname"), "old app dir after rename")
		mustExist(t, e.versionDir("newname", "1.0.0"), "moved version dir")
		// Имя файла внутри — прежнее (оно снято при загрузке и не следует
		// за переименованием); главное, что содержимое на месте.
		mustExist(t, e.versionDir("newname", "1.0.0")+"/"+defaultFileName("oldname", "1.0.0"),
			"moved binary")
		if dirs := e.topLevelDirs(); len(dirs) != 1 || dirs[0] != "newname" {
			t.Errorf("data dir contents = %v, want exactly [newname]", dirs)
		}
	})

	e.assertNoDanglingRows()
}

// TestRenameViaUIIsVisibleInAPI: то же переименование, но через UI-форму —
// API обязан увидеть новое имя, старое обязано перестать существовать.
func TestRenameViaUIIsVisibleInAPI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("uiold")
	content := e.seed("uiold", "1.1.0")
	// Клиент должен получить CSRF-куку со страницы приложения.
	e.uiPageBody(c, "/apps/uiold", http.StatusOK)

	resp := e.renameViaUI(c, "uiold", "uinew", "renamed via UI")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("UI edit: status = %d, want 303; body: %s", resp.StatusCode, readBody(t, resp))
	}
	if loc := resp.Header.Get("Location"); loc != "/apps/uinew" {
		t.Errorf("UI edit Location = %q, want /apps/uinew", loc)
	}

	status, m := e.appJSONOf("uinew")
	if status != http.StatusOK {
		t.Fatalf("API GET /api/apps/uinew: status = %d, want 200", status)
	}
	if m["description"] != "renamed via UI" {
		t.Errorf("description = %v, want %q", m["description"], "renamed via UI")
	}
	if status, _ := e.appJSONOf("uiold"); status != http.StatusNotFound {
		t.Errorf("API GET /api/apps/uiold: status = %d, want 404", status)
	}
	if got := e.mustDownload("uinew", "1.1.0"); !bytes.Equal(got, content) {
		t.Errorf("download after UI rename is not byte-identical")
	}
	e.wantDownloadStatus("uiold", "1.1.0", http.StatusNotFound)
	mustNotExist(t, e.appDir("uiold"), "old dir after UI rename")
	mustExist(t, e.versionDir("uinew", "1.1.0"), "new dir after UI rename")
	e.assertNoDanglingRows()
}

// TestRenameRoundTripKeepsBytes: переименовали туда и обратно — содержимое и
// раскладка на диске вернулись к исходным.
func TestRenameRoundTripKeepsBytes(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("round")
	content := e.seed("round", "0.1.0")

	for _, step := range []struct{ from, to string }{{"round", "trip"}, {"trip", "round"}} {
		resp := e.renameViaAPI(step.from, `{"name":"`+step.to+`"}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rename %s -> %s: status = %d; body: %s",
				step.from, step.to, resp.StatusCode, readBody(t, resp))
		}
		resp.Body.Close()
	}

	if got := e.mustDownload("round", "0.1.0"); !bytes.Equal(got, content) {
		t.Errorf("round trip changed the bytes")
	}
	if dirs := e.topLevelDirs(); len(dirs) != 1 || dirs[0] != "round" {
		t.Errorf("data dir after round trip = %v, want [round]", dirs)
	}
	e.assertNoDanglingRows()
}

// TestRenameAppWithoutVersions: у приложения без версий каталога на диске нет —
// переименование обязано пройти и не создать пустых каталогов.
func TestRenameAppWithoutVersions(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("empty")
	mustNotExist(t, e.appDir("empty"), "app without versions has no dir yet")

	resp := e.renameViaAPI("empty", `{"name":"stillempty","description":"d"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename empty app: status = %d, want 200; body: %s", resp.StatusCode, readBody(t, resp))
	}
	if status, m := e.appJSONOf("stillempty"); status != http.StatusOK {
		t.Errorf("GET renamed empty app: status = %d, want 200", status)
	} else if m["versions_count"] != float64(0) {
		t.Errorf("versions_count = %v, want 0", m["versions_count"])
	}
	if dirs := e.topLevelDirs(); len(dirs) != 0 {
		t.Errorf("renaming a version-less app created directories: %v", dirs)
	}

	// Загрузка после переименования кладёт файл уже под новым именем.
	content := e.seed("stillempty", "1.0.0")
	if got := e.mustDownload("stillempty", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("upload after renaming an empty app is not readable back")
	}
	e.assertNoDanglingRows()
}

// TestRenameToTakenNameIs409: имя занято — обе стороны отказывают и НИЧЕГО не
// теряют: обе строки в БД и оба каталога на месте, оба приложения качаются.
func TestRenameToTakenNameIs409(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("alpha")
	e.createApp("beta")
	alpha := e.seed("alpha", "1.0.0")
	beta := e.seed("beta", "1.0.0")

	t.Run("api_conflict", func(t *testing.T) {
		wantJSONError(t, e.renameViaAPI("alpha", `{"name":"beta"}`),
			http.StatusConflict, "already_exists")
	})

	t.Run("ui_conflict", func(t *testing.T) {
		e.uiPageBody(c, "/apps/alpha", http.StatusOK)
		resp := e.renameViaUI(c, "alpha", "beta", "test app")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("UI rename into a taken name: status = %d, want 409", resp.StatusCode)
		}
	})

	t.Run("nothing_was_lost", func(t *testing.T) {
		if status, _ := e.appJSONOf("alpha"); status != http.StatusOK {
			t.Errorf("alpha disappeared after the failed rename: status = %d", status)
		}
		if status, _ := e.appJSONOf("beta"); status != http.StatusOK {
			t.Errorf("beta disappeared after the failed rename: status = %d", status)
		}
		if got := e.mustDownload("alpha", "1.0.0"); !bytes.Equal(got, alpha) {
			t.Errorf("alpha bytes changed after the failed rename")
		}
		if got := e.mustDownload("beta", "1.0.0"); !bytes.Equal(got, beta) {
			t.Errorf("beta bytes changed after the failed rename")
		}
		if dirs := e.topLevelDirs(); len(dirs) != 2 {
			t.Errorf("data dir = %v, want both alpha and beta", dirs)
		}
	})

	e.assertNoDanglingRows()
}

// TestRenameToInvalidNameIsRejected: зарезервированное имя, traversal и пустое
// имя отбиваются на входе; приложение остаётся под старым именем.
func TestRenameToInvalidNameIsRejected(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("victim")
	content := e.seed("victim", "1.0.0")

	for _, bad := range []string{"latest", "../escape", "", ".hidden", "a/b"} {
		t.Run("api_rejects_"+url.PathEscape(bad), func(t *testing.T) {
			body, err := jsonBody(map[string]string{"name": bad})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			resp := e.renameViaAPI("victim", body)
			wantJSONError(t, resp, http.StatusBadRequest, "invalid_name")
		})
	}

	t.Run("ui_rejects_reserved_name", func(t *testing.T) {
		e.uiPageBody(c, "/apps/victim", http.StatusOK)
		resp := e.renameViaUI(c, "victim", "latest", "d")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("UI rename to \"latest\": status = %d, want 400", resp.StatusCode)
		}
	})

	if status, _ := e.appJSONOf("victim"); status != http.StatusOK {
		t.Errorf("victim gone after rejected renames: status = %d", status)
	}
	if got := e.mustDownload("victim", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("victim bytes changed after rejected renames")
	}
	if dirs := e.topLevelDirs(); len(dirs) != 1 || dirs[0] != "victim" {
		t.Errorf("data dir = %v, want [victim]", dirs)
	}
	e.assertNoDanglingRows()
}

// TestPatchDescriptionOnlyKeepsNameAndFiles: PATCH без поля name не трогает ни
// имя, ни каталог; пустое тело не меняет ничего.
func TestPatchDescriptionOnlyKeepsNameAndFiles(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("descapp")
	content := e.seed("descapp", "1.0.0")

	resp := e.renameViaAPI("descapp", `{"description":"only the text"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH description: status = %d, want 200", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["name"] != "descapp" || m["description"] != "only the text" {
		t.Errorf("PATCH description result = %v/%v, want descapp/only the text", m["name"], m["description"])
	}

	empty := e.api("PATCH", "/api/apps/descapp", strings.NewReader(""), jsonHdr)
	defer empty.Body.Close()
	if empty.StatusCode != http.StatusOK {
		t.Errorf("PATCH with an empty body: status = %d, want 200", empty.StatusCode)
	}
	if got := e.mustDownload("descapp", "1.0.0"); !bytes.Equal(got, content) {
		t.Errorf("description-only PATCH disturbed the stored file")
	}
	e.assertNoDanglingRows()
}
