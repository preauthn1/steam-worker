package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/preauthn1/steam-worker/internal/steam"
)

func TestCanceledWriteAndStateDurability(t *testing.T) {
	dir := t.TempDir()
	runs := 0
	ops := map[string]steam.Operation{"synthetic.cancel": {Name: "synthetic.cancel", Scope: "write", Mutating: true, Schema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, Run: func(ctx context.Context, c *steam.Context, args map[string]any) (any, error) {
		runs++
		c.State["guard"] = map[string]any{"shared_secret": "synthetic-guard"}
		return nil, ctx.Err()
	}}}
	config := Config{APIKeysJSON: testKeys(), StateKeyHex: strings.Repeat("66", 32), DataDir: dir, Registry: ops}
	h, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	admin := strings.Repeat("a", 32)
	request(h, "PUT", "/v1/accounts/alpha", admin, "create-key-00001", "{}")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/v1/accounts/alpha/operations/synthetic.cancel", strings.NewReader("{}"))
	r = r.WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+admin)
	r.Header.Set("X-Confirm-Write", "true")
	r.Header.Set("Idempotency-Key", "cancel-key-00001")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "outcome_unknown") {
		t.Fatal(w.Code, w.Body.String())
	}
	h.(*Server).Close()
	h, e = New(config)
	if e != nil {
		t.Fatal(e)
	}
	defer h.(*Server).Close()
	w = request(h, "POST", "/v1/accounts/alpha/operations/synthetic.cancel", admin, "cancel-key-00001", "{}")
	if w.Code != 409 || runs != 1 {
		t.Fatal("canceled retry", w.Code, runs)
	}
	w = request(h, "POST", "/v1/accounts/alpha/export", admin, "export-key-00001", "{}")
	var exported map[string]any
	if json.Unmarshal(w.Body.Bytes(), &exported) != nil {
		t.Fatal(w.Body.String())
	}
	v, _ := newVault(config.StateKeyHex, "alpha")
	var state map[string]any
	if e = v.open(exported["envelope"].(string), &state); e != nil {
		t.Fatal(e)
	}
	guard := state["state"].(map[string]any)["guard"].(map[string]any)
	if guard["shared_secret"] != "synthetic-guard" {
		t.Fatal("canceled state lost")
	}
}
func TestInvalidConfiguration(t *testing.T) {
	for _, c := range []Config{{}, {APIKeysJSON: testKeys(), DataDir: t.TempDir(), StateKeyHex: "bad"}, {APIKeysJSON: `[]`, StateKeyHex: strings.Repeat("11", 32), DataDir: t.TempDir()}, {APIKeysJSON: testKeys(), StateKeyHex: strings.Repeat("11", 32), DataDir: t.TempDir(), HTML: []byte("synthetic"), CSP: "bad\nheader"}} {
		if h, e := New(c); e == nil {
			h.(*Server).Close()
			t.Fatal("accepted invalid config")
		}
	}
}
