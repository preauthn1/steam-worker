package steam

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"
)

func findOperation(ops []Operation, name string) Operation {
	for _, op := range ops {
		if op.Name == name {
			return op
		}
	}
	panic(name)
}
func syntheticJWT(sub string, aud []string) string {
	b, _ := json.Marshal(map[string]any{"sub": sub, "aud": aud, "exp": time.Now().Unix() + 3600})
	return "synthetic." + base64.RawURLEncoding.EncodeToString(b) + ".synthetic"
}
func TestSessionLifecycle(t *testing.T) {
	ops := SessionOperations()
	if len(ops) != 9 {
		t.Fatal(len(ops))
	}
	c := &Context{State: State{}, Scope: "admin"}
	stage := 0
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		stage++
		var b []byte
		switch stage {
		case 1:
			w := new(ProtoWriter).Uint(1, 42).String(2, "https://s.team/q/1/42").Bytes(3, []byte("request"))
			b = w.Finish()
			b = append(b, 37)
			b = binary.LittleEndian.AppendUint32(b, math.Float32bits(1))
			b = append(b, new(ProtoWriter).Bytes(5, new(ProtoWriter).Uint(1, 4).Finish()).Uint(6, 1).Finish()...)
		case 2:
			b = new(ProtoWriter).String(3, syntheticJWT("7", []string{"web", "derive"})).String(4, syntheticJWT("7", []string{"web"})).Finish()
		default:
			return fakeResponse(500, "", nil), nil
		}
		return fakeResponse(200, string(b), nil), nil
	})
	v, e := findOperation(ops, "session.qr").Run(context.Background(), c, map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	handle := v.(map[string]any)["login_handle"]
	v, e = findOperation(ops, "session.poll").Run(context.Background(), c, map[string]any{"login_handle": handle})
	if e != nil || v.(map[string]any)["status"] != "authenticated" {
		t.Fatal(v, e)
	}
	if c.State["pending_login"] != nil {
		t.Fatal("pending retained")
	}
	v, e = findOperation(ops, "session.cookies").Run(context.Background(), c, map[string]any{})
	if e == nil {
		t.Fatal("web cookies require upstream transfer")
	}
	if _, e = findOperation(ops, "session.qr").Run(context.Background(), c, map[string]any{}); e == nil {
		t.Fatal("authenticated start permitted")
	}
}
func TestSessionLocalGates(t *testing.T) {
	ops := SessionOperations()
	c := &Context{State: State{}, Scope: "read", Transport: NewTransport()}
	if _, e := findOperation(ops, "session.status").Run(context.Background(), c, nil); e == nil {
		t.Fatal("scope gate")
	}
	c.Scope = "admin"
	if _, e := findOperation(ops, "guard.configure").Run(context.Background(), c, map[string]any{"shared_secret": "invalid"}); e == nil {
		t.Fatal("secret gate")
	}
	if _, e := findOperation(ops, "guard.configure").Run(context.Background(), c, map[string]any{"shared_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAA="}); e != nil {
		t.Fatal(e)
	}
	if _, e := findOperation(ops, "session.cancel").Run(context.Background(), c, map[string]any{"login_handle": "synthetic"}); e == nil {
		t.Fatal("missing pending gate")
	}
}
