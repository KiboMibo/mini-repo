package integration

// Хелперы для сквозных сценариев волны 5 (переименование и удаление,
// задачи T12–T14). Задача R5-test из docs/plans/2026-08-06-app-artifactory.md.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"apprepo/internal/store"
)

// --- HTTP-обёртки ---

// download fetches a binary through the API download route (Basic Auth).
func (e *env) download(app, version string) *http.Response {
	e.t.Helper()
	return e.api("GET", "/download/"+app+"/"+version, nil, nil)
}

// mustDownload asserts 200 and returns the body bytes.
func (e *env) mustDownload(app, version string) []byte {
	e.t.Helper()
	resp := e.download(app, version)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET /download/%s/%s: status = %d, want 200; body: %s",
			app, version, resp.StatusCode, readBody(e.t, resp))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read download body: %v", err)
	}
	return b
}

// wantDownloadStatus asserts the status of a download attempt.
func (e *env) wantDownloadStatus(app, version string, want int) {
	e.t.Helper()
	resp := e.download(app, version)
	defer resp.Body.Close()
	if resp.StatusCode != want {
		e.t.Errorf("GET /download/%s/%s: status = %d, want %d; body: %s",
			app, version, resp.StatusCode, want, readBody(e.t, resp))
	}
}

// uiPost submits an urlencoded form through the UI as a logged-in client.
func (e *env) uiPost(c *http.Client, path string, form url.Values) *http.Response {
	e.t.Helper()
	resp, err := c.PostForm(e.srv.URL+path, form)
	if err != nil {
		e.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// uiGet fetches a UI page as a logged-in client.
func (e *env) uiGet(c *http.Client, path string) *http.Response {
	e.t.Helper()
	resp, err := c.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// uiPageBody asserts the status of a UI page and returns its body.
func (e *env) uiPageBody(c *http.Client, path string, want int) string {
	e.t.Helper()
	resp := e.uiGet(c, path)
	defer resp.Body.Close()
	body := readBody(e.t, resp)
	if resp.StatusCode != want {
		e.t.Fatalf("GET %s: status = %d, want %d", path, resp.StatusCode, want)
	}
	return body
}

// appJSONOf returns the status and decoded body of GET /api/apps/{name}.
func (e *env) appJSONOf(name string) (int, map[string]any) {
	e.t.Helper()
	resp := e.api("GET", "/api/apps/"+name, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, decodeJSON(e.t, resp)
}

// latestOf returns the "version" of the app's latest object, or "" when null.
func (e *env) latestOf(name string) string {
	e.t.Helper()
	status, m := e.appJSONOf(name)
	if status != http.StatusOK {
		e.t.Fatalf("GET /api/apps/%s: status = %d, want 200", name, status)
	}
	latest, ok := m["latest"].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := latest["version"].(string)
	return v
}

// versionNamesOf returns the versions of an app as reported by the API.
func (e *env) versionNamesOf(name string) []string {
	e.t.Helper()
	resp := e.api("GET", "/api/apps/"+name+"/versions", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET versions of %s: status = %d, want 200", name, resp.StatusCode)
	}
	var arr []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
		e.t.Fatalf("decode versions of %s: %v", name, err)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, _ := v["version"].(string)
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// jsonBody marshals v so that tests can send names that would break a
// hand-written JSON literal (quotes, slashes, empty strings).
func jsonBody(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// --- посев данных ---

// seed uploads a deterministic payload for app/version over the API and
// returns the exact bytes that were stored, so tests can compare byte-for-byte.
func (e *env) seed(app, version string) []byte {
	e.t.Helper()
	content := payloadFor(app, version)
	e.mustPutVersion(app, version, "", content, sha256hex(content))
	return content
}

// payloadFor builds a payload that is unique per app+version and long enough
// that a truncated or swapped file is obvious in a diff.
func payloadFor(app, version string) []byte {
	return []byte(strings.Repeat("binary-of:"+app+"@"+version+";", 32))
}

// --- проверки диска ---

func (e *env) appDir(app string) string { return filepath.Join(e.dataDir, app) }

func (e *env) versionDir(app, version string) string {
	return filepath.Join(e.dataDir, app, version)
}

// defaultFileName is the name env.putVersion sends when a test does not pass its
// own ?filename= ({app}-{version}; the API has no default since T23). The stored
// name does NOT follow later renames of the app.
func defaultFileName(app, version string) string { return app + "-" + version }

func mustExist(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("%s: expected %s to exist, got %v", why, path, err)
	}
}

func mustNotExist(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("%s: expected %s to be gone, but it is still there", why, path)
	} else if !os.IsNotExist(err) {
		t.Errorf("%s: Lstat %s: %v", why, path, err)
	}
}

// topLevelDirs lists the app directories under the data dir, skipping the
// storage scratch dir and the SQLite files.
func (e *env) topLevelDirs() []string {
	e.t.Helper()
	ents, err := os.ReadDir(e.dataDir)
	if err != nil {
		e.t.Fatalf("ReadDir %s: %v", e.dataDir, err)
	}
	var out []string
	for _, ent := range ents {
		n := ent.Name()
		if n == ".tmp" || strings.HasPrefix(n, "apprepo.db") {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// --- инвариант хранилища ---

// assertNoDanglingRows walks every app and version in the database and checks
// that the file each row points at exists on disk with the recorded size, and
// that it is actually downloadable. This is the invariant the whole wave has
// to preserve: no row may point at a file that is not there.
func (e *env) assertNoDanglingRows() {
	e.t.Helper()
	apps, err := e.st.ListApps()
	if err != nil {
		e.t.Fatalf("ListApps: %v", err)
	}
	for _, a := range apps {
		vs, err := e.st.ListVersions(a.ID)
		if err != nil {
			e.t.Fatalf("ListVersions(%s): %v", a.Name, err)
		}
		for _, v := range vs {
			p := filepath.Join(e.dataDir, a.Name, v.Version, v.Filename)
			fi, err := os.Stat(p)
			if err != nil {
				e.t.Errorf("dangling row: app %q version %q points at %s: %v",
					a.Name, v.Version, p, err)
				continue
			}
			if fi.Size() != v.SizeBytes {
				e.t.Errorf("size mismatch for %s/%s: on disk %d, in DB %d",
					a.Name, v.Version, fi.Size(), v.SizeBytes)
			}
			got := e.mustDownload(a.Name, v.Version)
			if sha256hex(got) != v.SHA256 {
				e.t.Errorf("sha mismatch for %s/%s: downloaded %s, in DB %s",
					a.Name, v.Version, sha256hex(got), v.SHA256)
			}
		}
	}
}

// orphanDirs returns directories under the data dir that no app row claims.
// Used as an observation, not as a hard requirement: an orphan directory is
// harmless (unlike a dangling row) and the wave-5 reports call it out.
func (e *env) orphanDirs() []string {
	e.t.Helper()
	known := map[string]bool{}
	apps, err := e.st.ListApps()
	if err != nil {
		e.t.Fatalf("ListApps: %v", err)
	}
	for _, a := range apps {
		known[a.Name] = true
	}
	var out []string
	for _, d := range e.topLevelDirs() {
		if !known[d] {
			out = append(out, d)
		}
	}
	return out
}

// versionsByID is a small convenience for cascade checks after DeleteApp.
func (e *env) versionsOfID(id int64) []*store.Version {
	e.t.Helper()
	vs, err := e.st.ListVersions(id)
	if err != nil {
		e.t.Fatalf("ListVersions(%d): %v", id, err)
	}
	return vs
}
