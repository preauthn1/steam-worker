package server

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// Guard the exact embedded bytes, not a normalized copy of the inline sources.
func TestAssetsCSPHashes(t *testing.T) {
	html, csp := Assets()
	for _, tag := range []string{"script", "style"} {
		blocks := regexp.MustCompile(`(?s)<`+tag+`>(.*?)</`+tag+`>`).FindAllSubmatch(html, -1)
		if len(blocks) != 1 {
			t.Fatalf("expected exactly one inline %s block, got %d", tag, len(blocks))
		}
		digest := sha256.Sum256(blocks[0][1])
		want := tag + "-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing exact %s hash", tag)
		}
	}
	for _, directive := range []string{"default-src 'none'", "connect-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %s", directive)
		}
	}
	for _, unsafe := range []string{"unsafe-inline", "unsafe-eval", "https:", "http:", "cloudflareinsights"} {
		if strings.Contains(csp, unsafe) {
			t.Errorf("CSP unexpectedly permits %s", unsafe)
		}
	}
}
