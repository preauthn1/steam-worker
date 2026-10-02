package steam

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func mobileContext() *Context {
	return &Context{Scope: "admin", State: State{"session": map[string]any{"steam_id": "7", "platform": "mobile", "access_token": syntheticJWT("7", []string{"mobile"}), "access_expires_at": timestamp() + 3600}, "guard": map[string]any{"shared_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}
}
func TestQRConsumeBeforeFailure(t *testing.T) {
	ops := QRApprovalOperations()
	if len(ops) != 4 {
		t.Fatal(len(ops))
	}
	c := mobileContext()
	calls := 0
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return fakeResponse(200, string(new(ProtoWriter).Uint(8, 1).Uint(12, 1).String(7, "Synthetic Device").Finish()), nil), nil
		}
		return nil, errors.New("synthetic network failure")
	})
	v, e := findOperation(ops, "session.qr_inspect").Run(context.Background(), c, map[string]any{"qr_url": "https://s.team/q/1/42"})
	if e != nil {
		t.Fatal(e)
	}
	handle := v.(map[string]any)["review_handle"]
	if _, e := findOperation(ops, "session.qr_approve").Run(context.Background(), c, map[string]any{"review_handle": handle}); e == nil {
		t.Fatal("failure swallowed")
	}
	if c.State["qr_review"] != nil {
		t.Fatal("review not consumed")
	}
	if _, e := findOperation(ops, "session.qr_approve").Run(context.Background(), c, map[string]any{"review_handle": handle}); e == nil || calls != 2 {
		t.Fatal("review replayed")
	}
}
func TestQRStrictURL(t *testing.T) {
	for _, u := range []string{"https://s.team/q/01/42", "https://s.team:443/q/1/42", "https://s.team/q/1/18446744073709551616", "https://s.team/q/65536/42"} {
		if _, _, e := qrChallenge(u); e == nil {
			t.Fatal("noncanonical URL accepted")
		}
	}
}
func TestPublicOperations(t *testing.T) {
	ops := PublicOperations()
	if len(ops) != 2 {
		t.Fatal(len(ops))
	}
	c := &Context{Scope: "read", State: State{}, Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/ITwoFactorService/QueryTime/v1" {
			return fakeResponse(200, string(new(ProtoWriter).Uint(1, 42).Finish()), nil), nil
		}
		return fakeResponse(200, `{"success":true,"lowest_price":"$1.25","volume":"2"}`, nil), nil
	})}
	v, e := findOperation(ops, "public.server_time").Run(context.Background(), c, nil)
	if e != nil || v.(map[string]any)["server_time"] != "42" {
		t.Fatal(v, e)
	}
	v, e = findOperation(ops, "public.market.get_price_overview").Run(context.Background(), c, map[string]any{"obj": "Synthetic Item"})
	if e != nil || v.(map[string]any)["lowest_price_minor"] != float64(125) {
		t.Fatal(v, e)
	}
}
