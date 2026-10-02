package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/preauthn1/steam-worker/internal/server"
)

func env(name, fallback string) string {
	if x := os.Getenv(name); x != "" {
		return x
	}
	return fallback
}
func main() {
	if os.Getenv("API_KEYS_JSON") == "" || os.Getenv("STATE_KEY_HEX") == "" {
		log.Fatal("API_KEYS_JSON and STATE_KEY_HEX are required")
	}
	html, csp := server.Assets()
	if path := os.Getenv("CONSOLE_HTML_FILE"); path != "" {
		var e error
		html, e = os.ReadFile(path)
		if e != nil {
			log.Fatal("cannot read frontend")
		}
		csp = os.Getenv("CONSOLE_CSP")
		if csp == "" {
			log.Fatal("CONSOLE_CSP required with CONSOLE_HTML_FILE")
		}
	}
	handler, e := server.New(server.Config{APIKeysJSON: os.Getenv("API_KEYS_JSON"), StateKeyHex: os.Getenv("STATE_KEY_HEX"), DataDir: env("DATA_DIR", "./data"), HTML: html, CSP: csp})
	if e != nil {
		log.Fatal("server configuration/storage initialization failed")
	}
	defer handler.(interface{ Close() error }).Close()
	srv := &http.Server{Addr: env("BIND", "127.0.0.1:8892"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		if srv.Shutdown(shutdown) != nil {
			srv.Close()
		}
	}()
	if e = srv.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
		log.Fatal("HTTP listener failed")
	}
}
