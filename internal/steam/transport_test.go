package steam

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type syntheticRoundTrip func(*http.Request) (*http.Response, error)

func (f syntheticRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fakeTransport(f syntheticRoundTrip) *Transport {
	return NewTransportWithClient(&http.Client{Transport: f})
}
func fakeResponse(code int, body string, h http.Header) *http.Response {
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}
func TestTransportBoundaries(t *testing.T) {
	tr := fakeTransport(func(r *http.Request) (*http.Response, error) { return fakeResponse(200, "ok", nil), nil })
	for _, u := range []string{"http://example.invalid/", "https://example.invalid/", "https://steamcommunity.com:444/", "https://user@steamcommunity.com/"} {
		if _, e := tr.Request(context.Background(), "GET", u, nil, nil, ""); e == nil {
			t.Fatal("egress accepted")
		}
	}
	for i := 0; i < 40; i++ {
		if _, e := tr.Request(context.Background(), "GET", "https://steamcommunity.com/", nil, nil, ""); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := tr.Request(context.Background(), "GET", "https://steamcommunity.com/", nil, nil, ""); e == nil {
		t.Fatal("budget accepted")
	}
}
func TestCookiesPersistence(t *testing.T) {
	tr := NewTransport()
	u, _ := url.Parse("https://steamcommunity.com/a/b")
	tr.Jar.SetCookies(u, []*http.Cookie{{Name: "synthetic", Value: "value", Path: "/a", Secure: true}})
	state := State{"session": map[string]any{}}
	SaveCookies(tr, state)
	next := NewTransport()
	if e := LoadCookies(next, state); e != nil {
		t.Fatal(e)
	}
	if len(next.Jar.Cookies(u)) != 1 {
		t.Fatal("cookie lost")
	}
	other, _ := url.Parse("https://store.steampowered.com/a/b")
	if len(next.Jar.Cookies(other)) != 0 {
		t.Fatal("host-only leak")
	}
}
func TestTransportCrossOriginRedirect(t *testing.T) {
	calls := 0
	tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return fakeResponse(302, "", http.Header{"Location": []string{"https://store.steampowered.com/"}}), nil
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Method != "GET" {
			t.Fatal("credentials or POST leaked")
		}
		return fakeResponse(200, "ok", nil), nil
	})
	_, e := tr.Request(context.Background(), "POST", "https://steamcommunity.com/", http.Header{"Authorization": []string{"synthetic"}, "Cookie": []string{"synthetic=value"}}, []byte("synthetic"), "")
	if e != nil {
		t.Fatal(e)
	}
}
