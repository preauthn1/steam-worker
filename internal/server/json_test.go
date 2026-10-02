package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictBody(t *testing.T) {
	for _, raw := range []string{`{"arguments":{},"arguments":{}}`, `{"arguments":{"constructor":1}}`, `[]`, `null`, string([]byte{0xff}), strings.Repeat(`{"a":`, 40) + `0` + strings.Repeat(`}`, 40)} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		if _, e := readBody(r); e == nil {
			t.Fatalf("unsafe JSON accepted: %q", raw)
		}
	}
}
