package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/preauthn1/steam-worker/internal/steam"
)

func testKeys() string {
	rows := []map[string]any{}
	for _, p := range []struct{ id, token, scope, account string }{{"admin", strings.Repeat("a", 32), "admin", "*"}, {"reader", strings.Repeat("r", 32), "read", "alpha"}, {"wild", strings.Repeat("w", 32), "read", "*"}} {
		h := sha256.Sum256([]byte(p.token))
		rows = append(rows, map[string]any{"id": p.id, "sha256": hex.EncodeToString(h[:]), "scopes": []string{p.scope}, "accounts": []string{p.account}})
	}
	raw, _ := json.Marshal(rows)
	return string(raw)
}
func request(h http.Handler, method, path, token, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("X-Confirm-Write", "true")
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestHTTPBoundary(t *testing.T) {
	runs := 0
	ops := map[string]steam.Operation{"synthetic.write": {Name: "synthetic.write", Scope: "write", Mutating: true, Schema: map[string]any{"type": "object", "properties": map[string]any{}}, Run: func(context.Context, *steam.Context, map[string]any) (any, error) {
		runs++
		return map[string]any{"safe": true, "cookie": "synthetic"}, nil
	}}}
	h, e := New(Config{APIKeysJSON: testKeys(), StateKeyHex: strings.Repeat("11", 32), DataDir: t.TempDir(), Registry: ops, HTML: []byte("<html>synthetic</html>"), CSP: "default-src 'none'"})
	if e != nil {
		t.Fatal(e)
	}
	defer h.(interface{ Close() error }).Close()
	admin := strings.Repeat("a", 32)
	reader := strings.Repeat("r", 32)
	for _, tt := range []struct {
		method, path, token, key, body string
		status                         int
	}{{"GET", "/", "", "", "", 200}, {"GET", "/health", "", "", "", 200}, {"GET", "/v1/operations", "", "", "", 401}, {"PUT", "/v1/accounts/alpha", reader, "create-key-00001", "{}", 403}, {"PUT", "/v1/accounts/alpha", admin, "", "{}", 428}, {"PUT", "/v1/accounts/alpha", admin, "create-key-00001", "{}", 200}, {"GET", "/v1/accounts/alpha", reader, "", "", 200}, {"GET", "/v1/accounts/beta", reader, "", "", 403}, {"GET", "/v1/accounts/alpha", strings.Repeat("w", 32), "", "", 403}, {"GET", "/v1/accounts", reader, "", "", 403}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", reader, "write-key-000001", "{}", 403}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", admin, "write-key-000001", "{\"other\":1}", 400}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", admin, "write-key-000001", "{\"arguments\":[]}", 400}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", admin, "write-key-000001", "{}", 200}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", admin, "write-key-000001", "{}", 200}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", admin, "write-key-000002", strings.Repeat("a", 131073), 413}, {"POST", "/v1/accounts/alpha/operations/synthetic.write", admin, "write-key-000002", "{} {}", 400}, {"PATCH", "/v1/accounts/alpha", admin, "", "", 405}} {
		w := request(h, tt.method, tt.path, tt.token, tt.key, tt.body)
		if w.Code != tt.status {
			t.Fatalf("%s %s: %d %s", tt.method, tt.path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache header")
		}
		if strings.Contains(w.Body.String(), "synthetic\"}") {
			t.Fatal("secret response")
		}
	}
	if runs != 1 {
		t.Fatal("replayed operation", runs)
	}
	w := request(h, "GET", "/v1/accounts", admin, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alpha") {
		t.Fatal(w.Body.String())
	}
	w = request(h, "POST", "/v1/accounts/alpha/export", admin, "export-key-00001", "{}")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var exported map[string]any
	json.Unmarshal(w.Body.Bytes(), &exported)
	env := exported["envelope"].(string)
	body, _ := json.Marshal(map[string]any{"envelope": env})
	w = request(h, "POST", "/v1/accounts/alpha/import", admin, "import-key-00001", string(body))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	request(h, "PUT", "/v1/accounts/beta", admin, "create-beta-0001", "{}")
	w = request(h, "POST", "/v1/accounts/beta/import", admin, "import-beta-0001", string(body))
	if w.Code != 400 {
		t.Fatal("cross account import", w.Code)
	}
	w = request(h, "DELETE", "/v1/accounts/alpha", admin, "delete-key-00001", "{}")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(h, "GET", "/v1/accounts/alpha", admin, "", "")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
