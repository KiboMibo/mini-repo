package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// clearEnv unsets every APPREPO_* var Load reads, so the test does not depend
// on the environment it runs in (envOr treats "" as unset).
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"APPREPO_ADDR", "APPREPO_DATA_DIR", "APPREPO_DB", "APPREPO_BASE_URL", "APPREPO_MAX_UPLOAD"} {
		t.Setenv(k, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Addr:           ":8080",
		DataDir:        "/opt/apps",
		DBPath:         "/opt/apps/apprepo.db",
		BaseURL:        "http://localhost:8080",
		MaxUploadBytes: 2147483648,
	}
	if cfg != want {
		t.Errorf("Load() = %+v, want %+v", cfg, want)
	}
}

func TestLoadPrecedenceFlagOverEnvOverDefault(t *testing.T) {
	clearEnv(t)
	t.Setenv("APPREPO_ADDR", ":9000")
	t.Setenv("APPREPO_DATA_DIR", "/env/data")
	t.Setenv("APPREPO_MAX_UPLOAD", "1024")
	// base-url has no env value here, so it must fall through to the default.
	cfg, err := Load([]string{"-addr", ":7000", "-max-upload", "2048"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr != ":7000" {
		t.Errorf("Addr = %q, want flag value :7000", cfg.Addr)
	}
	if cfg.MaxUploadBytes != 2048 {
		t.Errorf("MaxUploadBytes = %d, want flag value 2048", cfg.MaxUploadBytes)
	}
	if cfg.DataDir != "/env/data" {
		t.Errorf("DataDir = %q, want env value /env/data", cfg.DataDir)
	}
	if cfg.BaseURL != "http://localhost:8080" {
		t.Errorf("BaseURL = %q, want default", cfg.BaseURL)
	}
}

func TestLoadDBPathDefaultsUnderDataDir(t *testing.T) {
	clearEnv(t)
	cfg, err := Load([]string{"-data-dir", "/srv/apps"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DBPath != "/srv/apps/apprepo.db" {
		t.Errorf("DBPath = %q, want /srv/apps/apprepo.db", cfg.DBPath)
	}
	// An explicit -db must not be rewritten.
	cfg, err = Load([]string{"-data-dir", "/srv/apps", "-db", "/var/lib/apprepo.db"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DBPath != "/var/lib/apprepo.db" {
		t.Errorf("DBPath = %q, want explicit /var/lib/apprepo.db", cfg.DBPath)
	}
}

// systemd EnvironmentFile keeps trailing blanks, and a file edited on Windows
// brings a CR; neither may reach a path or a number.
func TestLoadTrimsEnvValues(t *testing.T) {
	clearEnv(t)
	t.Setenv("APPREPO_ADDR", "  :9000\t")
	t.Setenv("APPREPO_DATA_DIR", "/srv/apps ")
	t.Setenv("APPREPO_BASE_URL", "https://apps.example.com\r\n")
	t.Setenv("APPREPO_MAX_UPLOAD", "2147483648\r")
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Addr:           ":9000",
		DataDir:        "/srv/apps",
		DBPath:         "/srv/apps/apprepo.db",
		BaseURL:        "https://apps.example.com",
		MaxUploadBytes: 2147483648,
	}
	if cfg != want {
		t.Errorf("Load() = %+v, want %+v", cfg, want)
	}
}

// The point of the fix: a bad value must produce a reportable error naming the
// value and the knob, and it must NOT be marked as already printed — otherwise
// the process exits silently, as it did in production.
func TestLoadInvalidMaxUpload(t *testing.T) {
	for _, v := range []string{"2G", "2147483648 # 2 GiB", "0", "-1", "1e9", "abc"} {
		t.Run(v, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("APPREPO_MAX_UPLOAD", v)
			_, err := Load(nil)
			if err == nil {
				t.Fatalf("Load(APPREPO_MAX_UPLOAD=%q) = nil error, want error", v)
			}
			if errors.Is(err, ErrPrinted) {
				t.Errorf("error marked ErrPrinted, so main would stay silent: %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, v) || !strings.Contains(msg, "max-upload") {
				t.Errorf("error %q must name the bad value and the setting", msg)
			}
		})
	}
}

// Flag syntax errors are printed by the flag package itself, so Load marks them
// to keep main from printing a duplicate.
func TestLoadFlagErrorIsMarkedPrinted(t *testing.T) {
	clearEnv(t)
	defer quietStderr(t)()
	_, err := Load([]string{"-nosuchflag"})
	if err == nil {
		t.Fatal("Load(-nosuchflag) = nil error, want error")
	}
	if !errors.Is(err, ErrPrinted) {
		t.Errorf("flag error not marked ErrPrinted, main would print a duplicate: %v", err)
	}
}

// quietStderr swallows the usage text the flag package writes to os.Stderr.
func quietStderr(t *testing.T) func() {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	old := os.Stderr
	os.Stderr = devnull
	return func() { os.Stderr = old; devnull.Close() }
}
