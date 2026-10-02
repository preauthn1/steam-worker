package server

import (
	"embed"
	"strings"
)

//go:embed assets/console.html assets/csp.txt
var assets embed.FS

// Assets returns the bundled frontend and its exact script-hash CSP.
func Assets() ([]byte, string) {
	html, _ := assets.ReadFile("assets/console.html")
	csp, _ := assets.ReadFile("assets/csp.txt")
	return html, strings.TrimSpace(string(csp))
}
