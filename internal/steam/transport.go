package steam

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var allowedHosts = map[string]bool{"steamcommunity.com": true, "store.steampowered.com": true, "login.steampowered.com": true, "help.steampowered.com": true, "api.steampowered.com": true, "checkout.steampowered.com": true, "steam.tv": true}

func validateURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] || (u.Port() != "" && u.Port() != "443") || u.User != nil {
		return nil, fail(400, "egress_denied")
	}
	return u, nil
}

type Transport struct {
	Jar    http.CookieJar
	client *http.Client
	mu     sync.Mutex
	count  int
}

func NewTransport() *Transport { return NewTransportWithClient(&http.Client{}) }
func NewTransportWithClient(client *http.Client) *Transport {
	if client == nil {
		client = &http.Client{}
	}
	c := *client
	c.Jar = nil
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Transport{Jar: &trackingJar{}, client: &c}
}
func (t *Transport) Count() int { t.mu.Lock(); defer t.mu.Unlock(); return t.count }
func (t *Transport) Request(ctx context.Context, method, target string, headers http.Header, body []byte, contentType string) (*Response, error) {
	u, e := validateURL(target)
	if e != nil {
		return nil, e
	}
	h := headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", "steam-worker")
	}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	for hop := 0; hop <= 10; hop++ {
		t.mu.Lock()
		if t.count >= 40 {
			t.mu.Unlock()
			return nil, fail(429, "upstream_request_budget")
		}
		t.count++
		t.mu.Unlock()
		active, cancel := context.WithTimeout(ctx, 25*time.Second)
		r, e := http.NewRequestWithContext(active, method, u.String(), bytes.NewReader(body))
		if e != nil {
			cancel()
			return nil, fail(504, "upstream_unreachable")
		}
		r.Header = h.Clone()
		if t.Jar != nil {
			r.Header.Del("Cookie")
			for _, c := range t.Jar.Cookies(u) {
				r.AddCookie(c)
			}
		}
		res, e := t.client.Do(r)
		if e != nil {
			cancel()
			return nil, fail(504, "upstream_unreachable")
		}
		if t.Jar != nil {
			t.Jar.SetCookies(u, res.Cookies())
			if j, ok := t.Jar.(*trackingJar); ok && j.limitError {
				res.Body.Close()
				cancel()
				return nil, fail(502, "cookie_limit")
			}
		}
		location := res.Header.Get("Location")
		if res.StatusCode >= 300 && res.StatusCode < 400 && location != "" {
			res.Body.Close()
			cancel()
			ref, er := url.Parse(location)
			if er != nil {
				return nil, fail(400, "egress_denied")
			}
			next, er := validateURL(u.ResolveReference(ref).String())
			if er != nil {
				return nil, er
			}
			if next.Hostname() != u.Hostname() {
				if (res.StatusCode == 307 || res.StatusCode == 308) && body != nil {
					return nil, fail(400, "cross_origin_body_redirect_denied")
				}
				h.Del("Authorization")
				h.Del("Cookie")
			}
			if res.StatusCode == 303 || ((res.StatusCode == 301 || res.StatusCode == 302) && method == "POST") {
				method = "GET"
				body = nil
			}
			u = next
			continue
		}
		b, er := io.ReadAll(io.LimitReader(res.Body, 8000001))
		res.Body.Close()
		cancel()
		if er != nil {
			return nil, fail(504, "upstream_unreachable")
		}
		if len(b) > 8000000 {
			return nil, fail(502, "upstream_response_too_large")
		}
		return &Response{res.StatusCode, u.String(), res.Header.Clone(), b}, nil
	}
	return nil, fail(502, "redirect_limit")
}

type persistedCookie struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Domain   string   `json:"domain"`
	Path     string   `json:"path"`
	HostOnly bool     `json:"hostOnly"`
	Secure   bool     `json:"secure"`
	Expires  *float64 `json:"expires"`
}
type trackingJar struct {
	mu         sync.Mutex
	cookies    []persistedCookie
	limitError bool
}

var cookieName = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
var cookieValueBad = regexp.MustCompile(`[\x00-\x20\x7f;,]`)
var cookiePathBad = regexp.MustCompile(`[\x00-\x20\x7f;]`)

func domainMatches(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}
func validCookie(c persistedCookie) bool {
	return cookieName.MatchString(c.Name) && len(c.Name) <= 256 && len(c.Value) <= 16384 && !cookieValueBad.MatchString(c.Value) && (allowedHosts[c.Domain] || c.Domain == "steampowered.com") && strings.HasPrefix(c.Path, "/") && !cookiePathBad.MatchString(c.Path) && (!c.HostOnly || allowedHosts[c.Domain])
}
func (j *trackingJar) put(c persistedCookie) {
	if !validCookie(c) {
		return
	}
	out := j.cookies[:0]
	for _, old := range j.cookies {
		if old.Name != c.Name || old.Domain != c.Domain || old.Path != c.Path {
			out = append(out, old)
		}
	}
	j.cookies = out
	if c.Expires != nil && *c.Expires <= timestamp() {
		return
	}
	if len(j.cookies) >= 256 {
		j.limitError = true
		return
	}
	j.cookies = append(j.cookies, c)
}
func (j *trackingJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if _, e := validateURL(u.String()); e != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, raw := range cookies {
		domain := strings.ToLower(strings.TrimPrefix(raw.Domain, "."))
		hostOnly := domain == ""
		if hostOnly {
			domain = u.Hostname()
		}
		if !domainMatches(u.Hostname(), domain) {
			continue
		}
		path := raw.Path
		if !strings.HasPrefix(path, "/") {
			path = u.Path
			at := strings.LastIndex(path, "/")
			if at <= 0 {
				path = "/"
			} else {
				path = path[:at]
			}
		}
		var expiry *float64
		if !raw.Expires.IsZero() {
			v := float64(raw.Expires.Unix())
			expiry = &v
		}
		if raw.MaxAge != 0 {
			v := timestamp() + float64(raw.MaxAge)
			expiry = &v
		}
		c := persistedCookie{raw.Name, raw.Value, domain, path, hostOnly, raw.Secure, expiry}
		if strings.HasPrefix(c.Name, "__Secure-") && !c.Secure {
			continue
		}
		if strings.HasPrefix(c.Name, "__Host-") && (!c.Secure || !c.HostOnly || c.Path != "/") {
			continue
		}
		j.put(c)
	}
}
func (j *trackingJar) Cookies(u *url.URL) []*http.Cookie {
	if _, e := validateURL(u.String()); e != nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	path := u.Path
	if path == "" {
		path = "/"
	}
	out := []*http.Cookie{}
	for _, c := range j.cookies {
		if c.Expires != nil && *c.Expires <= timestamp() {
			continue
		}
		if (c.HostOnly && c.Domain != u.Hostname()) || (!c.HostOnly && !domainMatches(u.Hostname(), c.Domain)) {
			continue
		}
		if path != c.Path && !(strings.HasPrefix(path, c.Path) && (strings.HasSuffix(c.Path, "/") || (len(path) > len(c.Path) && path[len(c.Path)] == '/'))) {
			continue
		}
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain, Secure: c.Secure})
	}
	for i := 1; i < len(out); i++ {
		for k := i; k > 0 && len(out[k].Path) > len(out[k-1].Path); k-- {
			out[k], out[k-1] = out[k-1], out[k]
		}
	}
	return out
}
func (j *trackingJar) export() []persistedCookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := []persistedCookie{}
	for _, c := range j.cookies {
		if c.Expires == nil || *c.Expires > timestamp() {
			out = append(out, c)
		}
	}
	return out
}
func LoadCookies(t *Transport, state State) error {
	j := &trackingJar{}
	s := object(state["session"])
	if s != nil {
		b, e := json.Marshal(s["cookies"])
		if e == nil {
			var entries []json.RawMessage
			if json.Unmarshal(b, &entries) == nil {
				for _, raw := range entries {
					var fields map[string]json.RawMessage
					var c persistedCookie
					if json.Unmarshal(raw, &fields) != nil || fields["hostOnly"] == nil || fields["secure"] == nil || fields["expires"] == nil {
						continue
					}
					if (string(fields["hostOnly"]) != "true" && string(fields["hostOnly"]) != "false") || (string(fields["secure"]) != "true" && string(fields["secure"]) != "false") {
						continue
					}
					if json.Unmarshal(raw, &c) == nil {
						j.put(c)
					}
				}
			}
		}
	}
	t.Jar = j
	if j.limitError {
		return fail(502, "cookie_limit")
	}
	return nil
}
func SaveCookies(t *Transport, state State) {
	s := object(state["session"])
	if s == nil {
		return
	}
	if j, ok := t.Jar.(*trackingJar); ok {
		b, _ := json.Marshal(j.export())
		var v []any
		json.Unmarshal(b, &v)
		s["cookies"] = v
	}
}
func CallService(ctx context.Context, t *Transport, iface, method string, request []byte, accessToken, httpMethod string) ([]byte, error) {
	if httpMethod == "" {
		httpMethod = "POST"
	}
	u := "https://api.steampowered.com/" + iface + "/" + method + "/v1"
	params := url.Values{"input_protobuf_encoded": []string{base64.StdEncoding.EncodeToString(request)}}
	if accessToken != "" {
		params.Set("access_token", accessToken)
	}
	var body []byte
	ct := ""
	if httpMethod == "GET" {
		u += "?" + params.Encode()
	} else {
		body = []byte(params.Encode())
		ct = "application/x-www-form-urlencoded"
	}
	r, e := t.Request(ctx, httpMethod, u, nil, body, ct)
	if e != nil {
		return nil, e
	}
	er := r.Headers.Get("x-eresult")
	if er != "" && er != "1" {
		n, e := strconv.Atoi(er)
		if e != nil {
			return nil, invalidResponse()
		}
		status := 502
		if n == 84 {
			return nil, fail(429, "upstream_rate_limited")
		}
		if n == 5 || n == 15 || n == 21 {
			status = 403
		}
		return nil, fail(status, "upstream_eresult_"+strconv.Itoa(n))
	}
	if r.Status == 429 {
		return nil, fail(429, "upstream_rate_limited")
	}
	if r.Status >= 400 {
		return nil, fail(502, "upstream_http_"+strconv.Itoa(r.Status))
	}
	return r.Body, nil
}
