package steam

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestCookieImportStrictTypes(t *testing.T) {
	for _, bad := range []map[string]any{{"hostOnly": nil}, {"secure": nil}, {"expires": "never"}, {"domain": "example.invalid"}} {
		entry := map[string]any{"name": "synthetic", "value": "v", "domain": "steamcommunity.com", "path": "/", "hostOnly": true, "secure": true, "expires": nil}
		for k, v := range bad {
			entry[k] = v
		}
		tr := NewTransport()
		if e := LoadCookies(tr, State{"session": map[string]any{"cookies": []any{entry}}}); e != nil {
			t.Fatal(e)
		}
		if len(tr.Jar.(*trackingJar).export()) != 0 {
			t.Fatal("malformed imported cookie accepted")
		}
	}
}
func TestQRDecisionWire(t *testing.T) {
	for _, approve := range []bool{true, false} {
		c := mobileContext()
		calls := 0
		c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return fakeResponse(200, string(new(ProtoWriter).Uint(8, 1).Uint(12, 1).Finish()), nil), nil
			}
			r.ParseForm()
			req, _ := base64.StdEncoding.DecodeString(r.Form.Get("input_protobuf_encoded"))
			m, e := DecodeProto(req)
			if e != nil {
				t.Fatal(e)
			}
			expected := uint64(0)
			if approve {
				expected = 1
			}
			if protoInt(m, 1) != 1 || protoInt(m, 2) != 42 || protoInt(m, 3) != 7 || protoInt(m, 5) != expected || protoInt(m, 6) != 1 || len(protoBytes(m, 4)) != 32 {
				t.Fatal("decision wire mismatch")
			}
			if hex.EncodeToString(protoBytes(m, 4)) != "61326feeb012fb1d709638359f99455c7da049c4ecba7e5620e04397278c4d10" {
				t.Fatal("signature mismatch")
			}
			return fakeResponse(200, "", nil), nil
		})
		ops := QRApprovalOperations()
		v, e := findOperation(ops, "session.qr_inspect").Run(context.Background(), c, map[string]any{"qr_url": "https://s.team/q/1/42"})
		if e != nil {
			t.Fatal(e)
		}
		name, status := "session.qr_deny", "denied"
		if approve {
			name, status = "session.qr_approve", "approved"
		}
		v, e = findOperation(ops, name).Run(context.Background(), c, map[string]any{"review_handle": v.(map[string]any)["review_handle"]})
		if e != nil || v.(map[string]any)["status"] != status || c.State["qr_review"] != nil {
			t.Fatal(v, e)
		}
	}
}
func TestQRMetadataRejects(t *testing.T) {
	for _, b := range [][]byte{new(ProtoWriter).Uint(12, 1).Finish(), new(ProtoWriter).Uint(8, 2).Finish(), new(ProtoWriter).Uint(8, 1).Uint(8, 1).Finish(), new(ProtoWriter).Uint(8, 1).Uint(10, 2).Finish(), new(ProtoWriter).Uint(8, 1).Bytes(1, []byte{255}).Finish(), new(ProtoWriter).Uint(8, 1).String(1, strings.Repeat("x", 2049)).Finish()} {
		if _, e := qrMetadata(b, 1); e == nil {
			t.Fatal("bad metadata accepted")
		}
	}
}
