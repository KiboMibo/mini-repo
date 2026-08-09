// Package config loads service configuration from flags and environment
// variables. Flags take precedence over env vars, env vars over defaults.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrPrinted wraps errors that the flag package has already reported to stderr
// together with the usage text (unknown flag, bad syntax, -h). Callers must not
// print those a second time; every other Load error is theirs to report.
var ErrPrinted = errors.New("already reported by the flag package")

type Config struct {
	Addr           string // listen address
	DataDir        string // root directory for stored binaries
	DBPath         string // SQLite database path
	BaseURL        string // external base URL for download links
	MaxUploadBytes int64  // max accepted upload body size
}

// Load parses args (flags after the subcommand, without the program name).
// Env vars serve as flag defaults, so explicit flags win.
func Load(args []string) (Config, error) {
	fs := flag.NewFlagSet("apprepo", flag.ContinueOnError)
	var cfg Config
	fs.StringVar(&cfg.Addr, "addr", envOr("APPREPO_ADDR", ":8080"), "listen address")
	fs.StringVar(&cfg.DataDir, "data-dir", envOr("APPREPO_DATA_DIR", "/opt/apps"), "binaries root directory")
	fs.StringVar(&cfg.DBPath, "db", envOr("APPREPO_DB", ""), "SQLite database path (default {data-dir}/apprepo.db)")
	fs.StringVar(&cfg.BaseURL, "base-url", envOr("APPREPO_BASE_URL", "http://localhost:8080"), "external base URL for download links")
	maxUpload := fs.String("max-upload", envOr("APPREPO_MAX_UPLOAD", "2147483648"), "max upload size in bytes")
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrPrinted, err)
	}
	n, err := strconv.ParseInt(*maxUpload, 10, 64)
	if err != nil || n <= 0 {
		return Config{}, fmt.Errorf("invalid max-upload value %q (APPREPO_MAX_UPLOAD or -max-upload): expected a positive number of bytes", *maxUpload)
	}
	cfg.MaxUploadBytes = n
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(cfg.DataDir, "apprepo.db")
	}
	return cfg, nil
}

// envOr trims the value: systemd EnvironmentFile keeps trailing spaces, and a
// file edited on Windows brings a CR — both break paths and numbers alike.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
