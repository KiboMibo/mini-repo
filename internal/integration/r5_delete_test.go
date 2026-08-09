package integration

// Сквозные сценарии удаления версий и приложений (волна 5). Проверяется
// реальное исчезновение файлов и каталогов с диска, каскад в БД,
// пересчёт latest и целостность соседей.

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func (e *env) deleteVersionAPI(app, version string) *http.Response {
	e.t.Helper()
	return e.api("DELETE", "/api/apps/"+app+"/versions/"+version, nil, nil)
}

func (e *env) deleteAppAPI(app string) *http.Response {
	e.t.Helper()
	return e.api("DELETE", "/api/apps/"+app, nil, nil)
}

func (e *env) deleteVersionUI(c *http.Client, app, version string) *http.Response {
	e.t.Helper()
	return e.uiPost(c, "/apps/"+app+"/versions/"+version+"/delete",
		url.Values{"csrf_token": {e.csrfOf(c)}})
}

func (e *env) deleteAppUI(c *http.Client, app, confirm string) *http.Response {
	e.t.Helper()
	return e.uiPost(c, "/apps/"+app+"/delete",
		url.Values{"csrf_token": {e.csrfOf(c)}, "confirm": {confirm}})
}

// TestDeleteVersionRemovesFileAndKeepsNeighbours: удалённая версия исчезает с
// диска целиком (файл и каталог версии), соседние версии живы и скачиваются,
// latest пересчитан.
func TestDeleteVersionRemovesFileAndKeepsNeighbours(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("multi")
	v1 := e.seed("multi", "1.0.0")
	v2 := e.seed("multi", "2.0.0")
	v3 := e.seed("multi", "3.0.0")
	_ = v3

	t.Run("delete_middle_version", func(t *testing.T) {
		resp := e.deleteVersionAPI("multi", "2.0.0")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE version: status = %d, want 204; body: %s", resp.StatusCode, readBody(t, resp))
		}
		mustNotExist(t, e.versionDir("multi", "2.0.0"), "deleted version dir")
		e.wantDownloadStatus("multi", "2.0.0", http.StatusNotFound)
		if got := e.versionNamesOf("multi"); strings.Join(got, ",") != "1.0.0,3.0.0" {
			t.Errorf("versions after delete = %v, want [1.0.0 3.0.0]", got)
		}
	})

	t.Run("neighbours_intact", func(t *testing.T) {
		if got := e.mustDownload("multi", "1.0.0"); !bytes.Equal(got, v1) {
			t.Errorf("1.0.0 damaged by deleting 2.0.0")
		}
		mustExist(t, e.versionDir("multi", "1.0.0"), "neighbour version dir")
		mustExist(t, e.versionDir("multi", "3.0.0"), "neighbour version dir")
	})

	t.Run("latest_recomputed_after_deleting_the_top", func(t *testing.T) {
		if got := e.latestOf("multi"); got != "3.0.0" {
			t.Fatalf("latest before deleting the top = %q, want 3.0.0", got)
		}
		resp := e.deleteVersionAPI("multi", "3.0.0")
		resp.Body.Close()
		if got := e.latestOf("multi"); got != "1.0.0" {
			t.Errorf("latest after deleting 3.0.0 = %q, want 1.0.0", got)
		}
		if got := e.mustDownload("multi", "latest"); !bytes.Equal(got, v1) {
			t.Errorf("/download/multi/latest does not serve 1.0.0 after the top was deleted")
		}
	})

	t.Run("deleting_a_missing_version_is_404", func(t *testing.T) {
		wantJSONError(t, e.deleteVersionAPI("multi", "2.0.0"), http.StatusNotFound, "not_found")
	})

	_ = v2
	e.assertNoDanglingRows()
}

// TestDeletePinnedVersionClearsOverride: удаление версии, закреплённой
// override, снимает пин (FK ON DELETE SET NULL) и latest снова резолвится в
// максимальный semver.
func TestDeletePinnedVersionClearsOverride(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("pinned")
	e.seed("pinned", "1.0.0")
	top := e.seed("pinned", "2.0.0")

	resp := e.api("POST", "/api/apps/pinned/latest", strings.NewReader(`{"version":"1.0.0"}`), jsonHdr)
	resp.Body.Close()
	if got := e.latestOf("pinned"); got != "1.0.0" {
		t.Fatalf("latest after pinning = %q, want 1.0.0", got)
	}
	app, err := e.st.GetApp("pinned")
	if err != nil || app == nil {
		t.Fatalf("GetApp(pinned): %v", err)
	}
	if app.LatestOverrideVersionID == nil {
		t.Fatal("override was not stored")
	}

	resp = e.deleteVersionAPI("pinned", "1.0.0")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE pinned version: status = %d, want 204", resp.StatusCode)
	}

	app, err = e.st.GetApp("pinned")
	if err != nil || app == nil {
		t.Fatalf("GetApp(pinned) after delete: %v", err)
	}
	if app.LatestOverrideVersionID != nil {
		t.Errorf("latest_override_version_id = %v after deleting the pinned version, want NULL",
			*app.LatestOverrideVersionID)
	}
	if got := e.latestOf("pinned"); got != "2.0.0" {
		t.Errorf("latest after unpinning = %q, want 2.0.0", got)
	}
	if got := e.mustDownload("pinned", "latest"); !bytes.Equal(got, top) {
		t.Errorf("/download/pinned/latest does not serve 2.0.0 after the pin was dropped")
	}
	e.assertNoDanglingRows()
}

// TestDeleteLastVersionLeavesAppAlive: удаление единственной версии оставляет
// приложение живым и пустым, а не удаляет его.
func TestDeleteLastVersionLeavesAppAlive(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("solo5")
	e.seed("solo5", "1.0.0")

	resp := e.deleteVersionAPI("solo5", "1.0.0")
	resp.Body.Close()

	status, m := e.appJSONOf("solo5")
	if status != http.StatusOK {
		t.Fatalf("app gone after deleting its last version: status = %d, want 200", status)
	}
	if m["versions_count"] != float64(0) {
		t.Errorf("versions_count = %v, want 0", m["versions_count"])
	}
	if m["latest"] != nil {
		t.Errorf("latest = %v, want null", m["latest"])
	}
	if got := e.versionNamesOf("solo5"); len(got) != 0 {
		t.Errorf("versions = %v, want empty", got)
	}
	e.wantDownloadStatus("solo5", "latest", http.StatusNotFound)
	mustNotExist(t, e.versionDir("solo5", "1.0.0"), "version dir after deleting the last version")

	// Приложение живо: в него можно снова загрузить ту же версию.
	again := e.seed("solo5", "1.0.0")
	if got := e.mustDownload("solo5", "1.0.0"); !bytes.Equal(got, again) {
		t.Errorf("re-uploading the deleted version did not work")
	}
	e.assertNoDanglingRows()
}

// TestDeleteAppRemovesEverythingAndSparesNeighbours: удаление приложения
// уносит каталог со всеми версиями, каскадом чистит строки версий и не задевает
// соседние приложения; повторное удаление — 404.
func TestDeleteAppRemovesEverythingAndSparesNeighbours(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	e.createApp("doomed")
	e.createApp("survivor")
	e.seed("doomed", "1.0.0")
	e.seed("doomed", "2.0.0")
	surv := e.seed("survivor", "1.0.0")

	doomed, err := e.st.GetApp("doomed")
	if err != nil || doomed == nil {
		t.Fatalf("GetApp(doomed): %v", err)
	}
	doomedID := doomed.ID

	resp := e.deleteAppAPI("doomed")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE app: status = %d, want 204; body: %s", resp.StatusCode, readBody(t, resp))
	}

	t.Run("directory_with_all_versions_is_gone", func(t *testing.T) {
		mustNotExist(t, e.appDir("doomed"), "app dir after delete")
		if dirs := e.topLevelDirs(); len(dirs) != 1 || dirs[0] != "survivor" {
			t.Errorf("data dir = %v, want [survivor]", dirs)
		}
	})

	t.Run("version_rows_cascaded", func(t *testing.T) {
		if vs := e.versionsOfID(doomedID); len(vs) != 0 {
			t.Errorf("%d version rows survived the app deletion, want 0 (ON DELETE CASCADE)", len(vs))
		}
	})

	t.Run("neighbour_untouched", func(t *testing.T) {
		if status, _ := e.appJSONOf("survivor"); status != http.StatusOK {
			t.Errorf("survivor gone: status = %d", status)
		}
		if got := e.mustDownload("survivor", "1.0.0"); !bytes.Equal(got, surv) {
			t.Errorf("survivor bytes changed")
		}
	})

	t.Run("second_delete_is_404", func(t *testing.T) {
		wantJSONError(t, e.deleteAppAPI("doomed"), http.StatusNotFound, "not_found")
		if status, _ := e.appJSONOf("doomed"); status != http.StatusNotFound {
			t.Errorf("GET deleted app: status = %d, want 404", status)
		}
		e.wantDownloadStatus("doomed", "1.0.0", http.StatusNotFound)
	})

	e.assertNoDanglingRows()
}

// TestDeleteViaUIVisibleInAPI: удалили приложение и версию через UI — API это
// видит немедленно.
func TestDeleteViaUIVisibleInAPI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("uidel")
	e.createApp("uikeep")
	e.seed("uidel", "1.0.0")
	e.seed("uidel", "2.0.0")
	keep := e.seed("uikeep", "1.0.0")
	e.uiPageBody(c, "/apps/uidel", http.StatusOK)

	t.Run("version_delete_via_ui", func(t *testing.T) {
		resp := e.deleteVersionUI(c, "uidel", "1.0.0")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("UI delete version: status = %d, want 303; body: %s", resp.StatusCode, readBody(t, resp))
		}
		if loc := resp.Header.Get("Location"); loc != "/apps/uidel" {
			t.Errorf("Location = %q, want /apps/uidel", loc)
		}
		if got := e.versionNamesOf("uidel"); strings.Join(got, ",") != "2.0.0" {
			t.Errorf("API versions after UI delete = %v, want [2.0.0]", got)
		}
		mustNotExist(t, e.versionDir("uidel", "1.0.0"), "version dir after UI delete")
		e.wantDownloadStatus("uidel", "1.0.0", http.StatusNotFound)
	})

	t.Run("app_delete_via_ui", func(t *testing.T) {
		resp := e.deleteAppUI(c, "uidel", "uidel")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("UI delete app: status = %d, want 303; body: %s", resp.StatusCode, readBody(t, resp))
		}
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Errorf("Location = %q, want /", loc)
		}
		if status, _ := e.appJSONOf("uidel"); status != http.StatusNotFound {
			t.Errorf("API still sees the app deleted via UI: status = %d, want 404", status)
		}
		mustNotExist(t, e.appDir("uidel"), "app dir after UI delete")
		if got := e.mustDownload("uikeep", "1.0.0"); !bytes.Equal(got, keep) {
			t.Errorf("neighbour damaged by the UI delete")
		}
	})

	e.assertNoDanglingRows()
}

// TestDeleteViaAPIVisibleInUI: обратная кросс-проверка — удалили через API,
// UI обязан отдать 404 на странице приложения и убрать его из списка.
func TestDeleteViaAPIVisibleInUI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("apidel")
	e.seed("apidel", "1.0.0")
	e.seed("apidel", "1.5.0")
	e.uiPageBody(c, "/apps/apidel", http.StatusOK)

	resp := e.deleteVersionAPI("apidel", "1.5.0")
	resp.Body.Close()
	page := e.uiPageBody(c, "/apps/apidel", http.StatusOK)
	if strings.Contains(page, "1.5.0") {
		t.Errorf("UI app page still shows the version deleted via API")
	}

	resp = e.deleteAppAPI("apidel")
	resp.Body.Close()
	appPage := e.uiGet(c, "/apps/apidel")
	appPage.Body.Close()
	if appPage.StatusCode != http.StatusNotFound {
		t.Errorf("UI app page after API delete: status = %d, want 404", appPage.StatusCode)
	}
	index := e.uiPageBody(c, "/", http.StatusOK)
	if strings.Contains(index, ">apidel<") {
		t.Errorf("UI index still lists the app deleted via API")
	}
	e.assertNoDanglingRows()
}

// TestDeleteVersionBadVersionIsRejected: несемверная версия — 400 в API,
// 404 в UI; ничего не удаляется.
func TestDeleteVersionBadVersionIsRejected(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.uiClient()
	e.login(c, "/")
	e.createApp("badver")
	content := e.seed("badver", "1.0.0")
	e.uiPageBody(c, "/apps/badver", http.StatusOK)

	wantJSONError(t, e.deleteVersionAPI("badver", "not-semver"), http.StatusBadRequest, "invalid_version")
	wantJSONError(t, e.deleteVersionAPI("badver", "9.9.9"), http.StatusNotFound, "not_found")

	resp := e.deleteVersionUI(c, "badver", "not-semver")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("UI delete of a non-semver version: status = %d, want 404", resp.StatusCode)
	}

	// "v1.0.0" каноникализуется в "1.0.0" — удаление обязано сработать.
	resp = e.deleteVersionAPI("badver", "v1.0.0")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE v1.0.0 (canonicalisable): status = %d, want 204", resp.StatusCode)
	}
	mustNotExist(t, e.versionDir("badver", "1.0.0"), "canonicalised version dir")
	_ = content
	e.assertNoDanglingRows()
}
