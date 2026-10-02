package server

import (
	"fmt"
	"log"
	"time"
)

// logAccess writes a single-line, secret-free access record: method, path
// (account slugs and operation names kept — not secrets — query string
// stripped), status, stable error code, and latency. No headers, tokens, or
// request/response bodies are ever logged.
func sanitizePath(path string) string {
	if i := indexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path
}
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
// logOutput is the sink for access log lines; overridable in tests.
var logOutput = func(line string) { log.Print(line) }

func logAccess(method, path string, status int, code string, elapsed time.Duration) {
	logOutput(fmt.Sprintf("access method=%s path=%s status=%d code=%s duration_ms=%d", method, sanitizePath(path), status, code, elapsed.Milliseconds()))
}
