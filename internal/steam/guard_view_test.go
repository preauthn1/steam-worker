package steam

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGuardViewOperations(t *testing.T) {
	ops := SessionOperations()
	rc := findOperation(ops, "guard.recovery_code")
	cc := findOperation(ops, "guard.code")
	c := &Context{State: State{}, Scope: "admin"}
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(200, "{}", nil), nil
	})
	// not configured
	if _, e := rc.Run(context.Background(), c, map[string]any{}); e == nil {
		t.Fatal("recovery_code should fail without guard")
	}
	if _, e := cc.Run(context.Background(), c, map[string]any{}); e == nil {
		t.Fatal("code should fail without guard")
	}
	// configured with valid base64 20-byte secret
	c.State["guard"] = map[string]any{
		"shared_secret":   "MDEyMzQ1Njc4OWFiY2RlZmdoaWo=",
		"revocation_code": "R12345",
	}
	out, e := rc.Run(context.Background(), c, map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	if out.(map[string]any)["revocation_code"] != "R12345" {
		t.Fatalf("recovery code %#v", out)
	}
	out2, e := cc.Run(context.Background(), c, map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	res := out2.(map[string]any)
	alpha := "23456789BCDFGHJKMNPQRTVWXY"
	code := res["code"].(string)
	if len(code) != 5 {
		t.Fatalf("totp len %#v", res)
	}
	for _, ch := range code {
		if !strings.ContainsRune(alpha, ch) {
			t.Fatalf("totp char %q not in alphabet: %#v", ch, res)
		}
	}
	var expiry float64
	switch v := res["expires_in"].(type) {
	case float64:
		expiry = v
	case int64:
		expiry = float64(v)
	case int:
		expiry = float64(v)
	default:
		t.Fatalf("expiry type %T %#v", res["expires_in"], res)
	}
	if expiry <= 0 || expiry > 30 {
		t.Fatalf("expiry %#v", res)
	}
}
