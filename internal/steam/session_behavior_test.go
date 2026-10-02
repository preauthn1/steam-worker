package steam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSessionDirectArgumentValidation(t *testing.T) {
	c := &Context{State: State{}, Scope: "admin", Transport: NewTransport()}
	if _, e := findOperation(SessionOperations(), "guard.configure").Run(context.Background(), c, map[string]any{"device_id": 123}); e == nil {
		t.Fatal("direct run accepted invalid args")
	}
}
func TestOperationCatalogJSON(t *testing.T) {
	for _, op := range append(append(SessionOperations(), QRApprovalOperations()...), PublicOperations()...) {
		b, e := json.Marshal(op)
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]any
		json.Unmarshal(b, &v)
		if v["name"] != op.Name || v["Name"] != nil || v["Run"] != nil {
			t.Fatal("invalid catalog serialization")
		}
	}
}
func TestRSACredentials(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 1024)
	if e != nil {
		t.Fatal(e)
	}
	c := &Context{Scope: "admin", State: State{"pending_login": map[string]any{"synthetic": "stale"}}}
	calls := 0
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			if c.State["pending_login"] != nil {
				t.Fatal("stale challenge retained")
			}
			return fakeResponse(200, string(new(ProtoWriter).String(1, fmt.Sprintf("%x", key.N)).String(2, fmt.Sprintf("%x", key.E)).Uint(3, 1).Finish()), nil), nil
		}
		if e := r.ParseForm(); e != nil {
			t.Fatal(e)
		}
		b, _ := base64.StdEncoding.DecodeString(r.Form.Get("input_protobuf_encoded"))
		m, _ := DecodeProto(b)
		cipher, _ := base64.StdEncoding.DecodeString(protoString(m, 3))
		plain, e := rsa.DecryptPKCS1v15(rand.Reader, key, cipher)
		if e != nil || string(plain) != "synthetic password" {
			t.Fatal("RSA payload mismatch", e)
		}
		d, _ := DecodeProto(protoBytes(m, 9))
		negative := int64(-500)
		if protoInt(d, 3) != uint64(negative) {
			t.Fatal("negative OS type mismatch")
		}
		return fakeResponse(500, "", nil), nil
	})
	if _, e := findOperation(SessionOperations(), "session.credentials").Run(context.Background(), c, map[string]any{"account_name": "synthetic", "password": "synthetic password", "platform": "mobile"}); e == nil || calls != 2 {
		t.Fatal("credentials request not exercised")
	}
}
func TestWebCookieTransferAndRefresh(t *testing.T) {
	access := syntheticJWT("7", []string{"web"})
	refresh := syntheticJWT("7", []string{"web", "derive"})
	s := map[string]any{"platform": "web", "steam_id": "7", "refresh_token": refresh, "access_token": access, "access_expires_at": timestamp() + 3600, "refresh_expires_at": timestamp() + 3600, "session_id": "synthetic", "cookies": []any{}}
	c := &Context{Scope: "admin", State: State{"session": s}}
	calls := 0
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		h := http.Header{}
		if r.URL.Path == "/jwt/finalizelogin" {
			if e := r.ParseMultipartForm(65536); e != nil {
				t.Fatal(e)
			}
			if r.FormValue("nonce") != refresh {
				t.Fatal("missing nonce")
			}
			return fakeResponse(200, `{"steamID":"7","transfer_info":[{"url":"https://steamcommunity.com/synthetic-transfer","params":{"nonce":"synthetic"}}]}`, nil), nil
		}
		if r.URL.Path == "/synthetic-transfer" {
			if e := r.ParseMultipartForm(65536); e != nil {
				t.Fatal(e)
			}
			if r.FormValue("steamID") != "7" {
				t.Fatal("missing steamID")
			}
			h.Add("Set-Cookie", "steamLoginSecure="+url.QueryEscape("7||"+access)+"; Path=/; Secure")
			return fakeResponse(200, "", h), nil
		}
		if r.URL.Path == "/jwt/refresh" {
			h.Add("Set-Cookie", "steamLoginSecure="+url.QueryEscape("7||"+access)+"; Domain=steamcommunity.com; Path=/; Secure")
			return fakeResponse(302, "", http.Header{"Location": []string{"https://steamcommunity.com/synthetic-refresh"}}), nil
		}
		if r.URL.Path == "/synthetic-refresh" {
			h.Add("Set-Cookie", "steamLoginSecure="+url.QueryEscape("7||"+access)+"; Path=/; Secure")
			return fakeResponse(200, "", h), nil
		}
		t.Fatal("unexpected path")
		return nil, nil
	})
	if _, e := findOperation(SessionOperations(), "session.cookies").Run(context.Background(), c, map[string]any{}); e != nil {
		t.Fatal(e)
	}
	if s["ready_for_web"] != true {
		t.Fatal("not ready")
	}
	if _, e := findOperation(SessionOperations(), "session.refresh").Run(context.Background(), c, map[string]any{}); e != nil {
		t.Fatal(e)
	}
	if calls != 4 {
		t.Fatal(calls)
	}
}
func TestMobileCookiesAndRefresh(t *testing.T) {
	access := syntheticJWT("7", []string{"mobile"})
	refresh := syntheticJWT("7", []string{"mobile", "derive"})
	s := map[string]any{"platform": "mobile", "steam_id": "7", "refresh_token": refresh, "access_token": access, "access_expires_at": timestamp() - 1, "refresh_expires_at": timestamp() + 3600, "cookies": []any{}}
	c := &Context{Scope: "admin", State: State{"session": s}, Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(200, string(new(ProtoWriter).String(1, access).String(2, refresh).Finish()), nil), nil
	})}
	if _, e := findOperation(SessionOperations(), "session.cookies").Run(context.Background(), c, map[string]any{}); e != nil {
		t.Fatal(e)
	}
	if c.Transport.Count() != 1 {
		t.Fatal("refresh omitted")
	}
	u, _ := url.Parse("https://steamcommunity.com/")
	if len(c.Transport.Jar.Cookies(u)) != 2 {
		t.Fatal("mobile cookies omitted")
	}
	if _, e := findOperation(SessionOperations(), "session.refresh").Run(context.Background(), c, map[string]any{"renew_refresh_token": true}); e != nil {
		t.Fatal(e)
	}
	if len(s["cookies"].([]any)) != 0 || s["ready_for_web"] != false {
		t.Fatal("stale cookies retained")
	}
}
func TestTransport307BodyAndCap(t *testing.T) {
	tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(307, "", http.Header{"Location": []string{"https://store.steampowered.com/"}}), nil
	})
	if _, e := tr.Request(context.Background(), "POST", "https://steamcommunity.com/", nil, []byte("synthetic"), ""); e == nil {
		t.Fatal("cross-host body replay allowed")
	}
	tr = fakeTransport(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(200, strings.Repeat("x", 8000001), nil), nil
	})
	if _, e := tr.Request(context.Background(), "GET", "https://steamcommunity.com/", nil, nil, ""); e == nil {
		t.Fatal("oversize accepted")
	}
}
