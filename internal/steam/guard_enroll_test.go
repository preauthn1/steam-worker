package steam

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// Synthetic end-to-end guard enrollment: AddAuthenticator returns secrets,
// FinalizeAddAuthenticator confirms, and the guard state ends active with
// secrets stored only in encrypted state (never in the response).
func TestGuardEnrollLifecycle(t *testing.T) {
	ops := SessionOperations()
	enroll := findOperation(ops, "guard.enroll")
	finalize := findOperation(ops, "guard.finalize")
	shared := base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghij"))
	identity := base64.StdEncoding.EncodeToString([]byte("abcdefghij0123456789"))
	rawShared, _ := base64.StdEncoding.DecodeString(shared)
	rawIdentity, _ := base64.StdEncoding.DecodeString(identity)
	c := &Context{State: State{}, Scope: "admin"}
	stage := 0
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		stage++
		var body []byte
		switch stage {
		case 1: // AddAuthenticator
			body = new(ProtoWriter).Bytes(1, rawShared).Uint(2, 12345).String(3, "R12345").String(7, "token-gid").Bytes(8, rawIdentity).Uint(10, 1).String(11, "+86 ***").Finish()
		case 2: // FinalizeAddAuthenticator
			body = new(ProtoWriter).Bool(1, true).Uint(3, 1700000000).Uint(4, 1).Finish()
		}
		return fakeResponse(200, string(body), nil), nil
	})
	c.State["session"] = map[string]any{
		"platform": "mobile", "steam_id": "76561199000000001",
		"access_token": syntheticJWT("76561199000000001", []string{"mobile"}),
		"access_expires_at": float64(timestamp() + 3600),
		"refresh_token": syntheticJWT("76561199000000001", []string{"mobile", "derive"}),
		"refresh_expires_at": float64(timestamp() + 86400),
	}
	out, e := enroll.Run(context.Background(), c, map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	res, ok := out.(map[string]any)
	if !ok || res["status"] != "activation_required" {
		t.Fatalf("enroll result %#v", out)
	}
	if s := stringify(res); strings.Contains(s, shared) || strings.Contains(s, identity) {
		t.Fatal("secrets leaked in enroll response")
	}
	g := object(c.State["guard"])
	if g["shared_secret"] != shared || g["enrollment"] != "pending_finalize" {
		t.Fatalf("guard state %#v", c.State["guard"])
	}
	out2, e := finalize.Run(context.Background(), c, map[string]any{"activation_code": "ABCDE"})
	if e != nil {
		t.Fatal(e)
	}
	res2 := out2.(map[string]any)
	if res2["status"] != "active" {
		t.Fatalf("finalize result %#v", out2)
	}
	if object(c.State["guard"])["enrollment"] != "active" {
		t.Fatal("guard not marked active")
	}
}

// Finalize before enroll must fail; wrong session platform must fail.
func TestGuardEnrollGuards(t *testing.T) {
	ops := SessionOperations()
	enroll := findOperation(ops, "guard.enroll")
	finalize := findOperation(ops, "guard.finalize")
	c := &Context{State: State{}, Scope: "admin"}
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(200, string(new(ProtoWriter).Bool(1, true).Finish()), nil), nil
	})
	if _, e := finalize.Run(context.Background(), c, map[string]any{"activation_code": "ABCD"}); e == nil {
		t.Fatal("finalize without enroll should fail")
	}
	c.State["session"] = map[string]any{"platform": "web", "steam_id": "76561199000000001", "refresh_token": "x", "refresh_expires_at": float64(timestamp() + 100)}
	if _, e := enroll.Run(context.Background(), c, map[string]any{}); e == nil {
		t.Fatal("enroll with web session should fail")
	}
}

func stringify(v any) string {
	return strings.ReplaceAll(strings.ReplaceAll(mapToStr(v), "\"", ""), "'", "")
}
func mapToStr(v any) string {
	switch x := v.(type) {
	case map[string]any:
		out := ""
		for k, val := range x {
			out += k + ":" + mapToStr(val) + ","
		}
		return out
	case []any:
		out := ""
		for _, val := range x {
			out += mapToStr(val) + ","
		}
		return out
	default:
		return toStrDefault(v)
	}
}
func toStrDefault(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
