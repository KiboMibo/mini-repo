// Package app wires the full service together: store, file storage, auth
// and the HTTP mux. Вынесено из main, чтобы интеграционные тесты могли
// поднять полное приложение через httptest.
package app

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"apprepo/internal/api"
	"apprepo/internal/auth"
	"apprepo/internal/config"
	"apprepo/internal/files"
	"apprepo/internal/store"
	"apprepo/internal/web"
)

// New builds the complete application: creates the data directory, opens the
// store and returns the fully-wired handler (UI + API + /healthz). The caller
// owns the returned store and must Close it.
func New(cfg config.Config) (http.Handler, *store.Store, error) {
	// 0700: в data-dir лежит БД с сессионными токенами и хешами паролей —
	// другим локальным пользователям хоста туда хода нет.
	for _, dir := range []string{cfg.DataDir, filepath.Dir(cfg.DBPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, err
		}
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, nil, err
	}
	a := &auth.Auth{Store: st}
	fst := &files.Storage{Root: cfg.DataDir}
	backfillPlatforms(st, fst)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	web.Register(mux, st, fst, a, cfg)
	api.Register(mux, st, fst, a, cfg)
	return mux, st, nil
}
