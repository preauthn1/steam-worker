package steam

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func randomHandle() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b)
}
func authService(ctx context.Context, c *Context, method string, w *ProtoWriter, httpMethod string) (map[int][]ProtoField, error) {
	b, e := CallService(ctx, c.Transport, "IAuthenticationService", method, w.Finish(), "", httpMethod)
	if e != nil {
		return nil, e
	}
	m, e := DecodeProto(b)
	if e != nil {
		return nil, invalidResponse()
	}
	return m, nil
}
func loginPlatform(args map[string]any) (string, error) {
	p := textValue(args["platform"])
	if p == "" {
		p = "web"
	}
	if p != "web" && p != "mobile" {
		return "", fail(400, "invalid_arguments")
	}
	return p, nil
}
func deviceMessage(p, name string) []byte {
	w := new(ProtoWriter).String(1, name)
	if p == "mobile" {
		negative := int64(-500)
		w.Uint(2, 3).Uint(3, uint64(negative)).Uint(4, 528)
	} else {
		w.Uint(2, 2)
	}
	return w.Finish()
}

var loginChallengePattern = regexp.MustCompile(`^/q/[0-9]+/[0-9]+$`)

func loginChallenge(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host != "s.team" || u.User != nil || !loginChallengePattern.MatchString(u.Path) || u.RawQuery != "" || u.Fragment != "" {
		return "", invalidResponse()
	}
	return raw, nil
}
func startLogin(c *Context) error {
	if textValue(object(c.State["session"])["refresh_token"]) != "" {
		return fail(409, "session_already_authenticated")
	}
	delete(c.State, "pending_login")
	return nil
}
func pendingResult(p map[string]any) map[string]any {
	return map[string]any{"status": "pending", "login_handle": p["login_handle"], "poll_interval": p["poll_interval"], "expires_at": p["expires_at"], "challenge_url": p["challenge_url"], "version": p["version"], "allowed_confirmations": p["allowed_confirmations"]}
}
func persistLogin(c *Context, m map[int][]ProtoField, platform string, qr bool) (any, error) {
	requestField, intervalField, confirmField := 2, 3, 4
	if qr {
		requestField, intervalField, confirmField = 3, 4, 5
	}
	fields := m[intervalField]
	if len(fields) == 0 || fields[0].Wire != 5 {
		return nil, invalidResponse()
	}
	interval := float64(math.Float32frombits(uint32(fields[0].Uint)))
	if interval <= 0 || interval > 600 || math.IsNaN(interval) || math.IsInf(interval, 0) {
		return nil, invalidResponse()
	}
	allowed := []any{}
	for _, f := range m[confirmField] {
		a, e := DecodeProto(f.Bytes)
		n := protoInt(a, 1)
		if e != nil || n < 1 || n > 7 {
			return nil, invalidResponse()
		}
		allowed = append(allowed, map[string]any{"confirmation_type": float64(n), "associated_message": protoString(a, 2)})
	}
	client := protoInt(m, 1)
	request := protoBytes(m, requestField)
	steam := protoInt(m, 5)
	if client == 0 || len(request) == 0 || len(allowed) == 0 || (!qr && steam == 0) {
		return nil, invalidResponse()
	}
	p := map[string]any{"login_handle": randomHandle(), "client_id": strconv.FormatUint(client, 10), "request_id": base64.StdEncoding.EncodeToString(request), "poll_interval": interval, "next_poll_at": float64(0), "expires_at": timestamp() + 600, "attempts": float64(0), "platform": platform, "allowed_confirmations": allowed, "steam_id": nil, "challenge_url": nil, "version": nil}
	if qr {
		u, e := loginChallenge(protoString(m, 2))
		if e != nil {
			return nil, e
		}
		p["challenge_url"] = u
		p["version"] = float64(protoInt(m, 6))
	} else {
		p["steam_id"] = strconv.FormatUint(steam, 10)
	}
	c.State["pending_login"] = p
	return pendingResult(p), nil
}
func pendingLogin(c *Context, args map[string]any, attempt bool) (map[string]any, error) {
	p := object(c.State["pending_login"])
	if p == nil || textValue(p["client_id"]) == "" || textValue(p["request_id"]) == "" || textValue(p["login_handle"]) == "" {
		return nil, fail(409, "login_required")
	}
	if p["login_handle"] != args["login_handle"] {
		return nil, fail(409, "login_handle_mismatch")
	}
	if number(p["expires_at"]) <= timestamp() {
		delete(c.State, "pending_login")
		return nil, fail(409, "login_expired")
	}
	if attempt {
		n := number(p["attempts"])
		if n >= 30 {
			return nil, fail(429, "login_attempt_limit")
		}
		p["attempts"] = n + 1
	}
	return p, nil
}

type tokenClaims struct {
	Sub string   `json:"sub"`
	Exp float64  `json:"exp"`
	Aud []string `json:"aud"`
}

var positiveID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func jwtClaims(raw string) (tokenClaims, error) {
	var claims tokenClaims
	parts := strings.Split(raw, ".")
	if len(raw) > 16384 || len(parts) != 3 {
		return claims, invalidResponse()
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if e != nil || json.Unmarshal(b, &claims) != nil || !positiveID.MatchString(claims.Sub) || claims.Exp <= timestamp() || claims.Aud == nil {
		return claims, invalidResponse()
	}
	if _, e := strconv.ParseUint(claims.Sub, 10, 64); e != nil {
		return claims, invalidResponse()
	}
	return claims, nil
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func tokenMetadata(access, refresh, p, expected string) (map[string]any, error) {
	a, e := jwtClaims(access)
	if e != nil {
		return nil, e
	}
	r, e := jwtClaims(refresh)
	if e != nil {
		return nil, e
	}
	if a.Sub != r.Sub || (expected != "" && expected != a.Sub) || contains(a.Aud, "derive") || !contains(r.Aud, "derive") || !contains(a.Aud, p) || !contains(r.Aud, p) {
		return nil, invalidResponse()
	}
	return map[string]any{"steam_id": a.Sub, "access_expires_at": a.Exp, "refresh_expires_at": r.Exp}, nil
}
func activeSession(c *Context) (map[string]any, error) {
	s := object(c.State["session"])
	if textValue(s["refresh_token"]) == "" || textValue(s["steam_id"]) == "" {
		return nil, fail(409, "session_required")
	}
	if number(s["refresh_expires_at"]) <= timestamp() {
		return nil, fail(409, "session_expired")
	}
	return s, nil
}
func sessionCredentials(ctx context.Context, c *Context, args map[string]any) (any, error) {
	if e := startLogin(c); e != nil {
		return nil, e
	}
	p, e := loginPlatform(args)
	if e != nil {
		return nil, e
	}
	name := textValue(args["device_friendly_name"])
	if name == "" {
		name = "Steam Worker"
	}
	m, e := authService(ctx, c, "GetPasswordRSAPublicKey", new(ProtoWriter).String(1, textValue(args["account_name"])), "GET")
	if e != nil {
		return nil, e
	}
	if protoString(m, 1) == "" || protoString(m, 2) == "" || protoInt(m, 3) == 0 {
		return nil, invalidResponse()
	}
	encrypted, e := encryptPassword(textValue(args["password"]), protoString(m, 1), protoString(m, 2))
	if e != nil {
		return nil, e
	}
	persist := args["persistence"] != false
	pt := uint64(2)
	site := "Community"
	if p == "mobile" {
		pt = 3
		site = "Mobile"
	}
	w := new(ProtoWriter).String(1, name).String(2, textValue(args["account_name"])).String(3, encrypted).Uint(4, protoInt(m, 3)).Bool(5, persist).Uint(6, pt).Bool(7, persist).String(8, site).Bytes(9, deviceMessage(p, name)).Uint(11, 0).Uint(12, 2)
	m, e = authService(ctx, c, "BeginAuthSessionViaCredentials", w, "")
	if e != nil {
		return nil, e
	}
	return persistLogin(c, m, p, false)
}
func sessionQR(ctx context.Context, c *Context, args map[string]any) (any, error) {
	if e := startLogin(c); e != nil {
		return nil, e
	}
	p, e := loginPlatform(args)
	if e != nil || p != "web" {
		return nil, fail(400, "invalid_arguments")
	}
	name := textValue(args["device_friendly_name"])
	if name == "" {
		name = "Steam Worker"
	}
	m, e := authService(ctx, c, "BeginAuthSessionViaQR", new(ProtoWriter).String(1, name).Uint(2, 2).Bytes(3, deviceMessage("web", name)).String(4, "Community"), "")
	if e != nil {
		return nil, e
	}
	return persistLogin(c, m, "web", true)
}
func sessionCode(ctx context.Context, c *Context, args map[string]any) (any, error) {
	p, e := pendingLogin(c, args, true)
	if e != nil {
		return nil, e
	}
	kind := textValue(args["code_type"])
	if kind == "" {
		kind = "device"
	}
	if (kind != "device" && kind != "email") || textValue(p["steam_id"]) == "" {
		return nil, fail(400, "invalid_arguments")
	}
	n := uint64(3)
	if kind == "email" {
		n = 2
	}
	allowed := false
	entries, _ := p["allowed_confirmations"].([]any)
	for _, v := range entries {
		if number(object(v)["confirmation_type"]) == float64(n) {
			allowed = true
		}
	}
	if !allowed {
		return nil, fail(409, "guard_code_not_allowed")
	}
	_, e = authService(ctx, c, "UpdateAuthSessionWithSteamGuardCode", new(ProtoWriter).Uint(1, decimal(p["client_id"])).Fixed64(2, decimal(p["steam_id"])).String(3, textValue(args["auth_code"])).Uint(4, n), "")
	var api *APIError
	if e != nil && (!errors.As(e, &api) || api.Code != "upstream_eresult_29") {
		return nil, e
	}
	return map[string]any{"status": "pending", "login_handle": p["login_handle"]}, nil
}
func sessionPoll(ctx context.Context, c *Context, args map[string]any) (any, error) {
	p, e := pendingLogin(c, args, false)
	if e != nil {
		return nil, e
	}
	if timestamp() < number(p["next_poll_at"]) {
		return nil, fail(429, "poll_too_soon")
	}
	if _, e = pendingLogin(c, args, true); e != nil {
		return nil, e
	}
	p["next_poll_at"] = timestamp() + number(p["poll_interval"])
	request, e := base64.StdEncoding.DecodeString(textValue(p["request_id"]))
	if e != nil {
		return nil, invalidResponse()
	}
	m, e := authService(ctx, c, "PollAuthSessionStatus", new(ProtoWriter).Uint(1, decimal(p["client_id"])).Bytes(2, request), "")
	if e != nil {
		var api *APIError
		if errors.As(e, &api) && (api.Code == "upstream_eresult_27" || api.Code == "upstream_eresult_5" || api.Code == "upstream_eresult_15") {
			delete(c.State, "pending_login")
		}
		return nil, e
	}
	if n := protoInt(m, 1); n != 0 {
		p["client_id"] = strconv.FormatUint(n, 10)
	}
	if u := protoString(m, 2); u != "" {
		v, e := loginChallenge(u)
		if e != nil {
			return nil, e
		}
		p["challenge_url"] = v
	}
	refresh, access := protoString(m, 3), protoString(m, 4)
	if refresh == "" {
		return pendingResult(p), nil
	}
	if access == "" {
		return nil, invalidResponse()
	}
	s, e := tokenMetadata(access, refresh, textValue(p["platform"]), textValue(p["steam_id"]))
	if e != nil {
		return nil, e
	}
	s["access_token"] = access
	s["refresh_token"] = refresh
	s["platform"] = p["platform"]
	s["session_id"] = randomHandle()[:24]
	s["cookies"] = []any{}
	s["account_name"] = nil
	if n := protoString(m, 6); n != "" {
		s["account_name"] = n
	}
	if g := protoString(m, 7); g != "" {
		s["guard_data"] = g
	}
	c.State["session"] = s
	c.State["authenticated"] = true
	delete(c.State, "pending_login")
	return map[string]any{"status": "authenticated", "steam_id": s["steam_id"], "ready_for_web": false}, nil
}
func putCookie(j *trackingJar, name, value, host string, expiry *float64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.put(persistedCookie{name, value, host, "/", true, true, expiry})
}
func encodeCookie(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
func seedCookies(j *trackingJar, s map[string]any) {
	expiry := number(s["refresh_expires_at"])
	putCookie(j, "steamRefresh_steam", encodeCookie(textValue(s["steam_id"])+"||"+textValue(s["refresh_token"])), "login.steampowered.com", &expiry)
	putCookie(j, "sessionid", textValue(s["session_id"]), "login.steampowered.com", nil)
}
func multipartFields(fields map[string]string) ([]byte, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		if e := w.WriteField(k, v); e != nil {
			return nil, "", invalidResponse()
		}
	}
	if e := w.Close(); e != nil {
		return nil, "", invalidResponse()
	}
	return b.Bytes(), w.FormDataContentType(), nil
}
func cookieToken(j *trackingJar, host, name string, s map[string]any, refresh bool) (string, error) {
	u, _ := url.Parse("https://" + host + "/")
	for _, c := range j.Cookies(u) {
		if c.Name != name {
			continue
		}
		value, e := url.PathUnescape(c.Value)
		if e != nil {
			return "", invalidResponse()
		}
		pair := strings.SplitN(value, "||", 2)
		if len(pair) != 2 || pair[0] != s["steam_id"] {
			return "", invalidResponse()
		}
		meta, e := jwtClaims(pair[1])
		if e != nil {
			return "", e
		}
		web := contains(meta.Aud, "web")
		for _, a := range meta.Aud {
			if strings.HasPrefix(a, "web:") {
				web = true
			}
		}
		if meta.Sub != s["steam_id"] || contains(meta.Aud, "derive") != refresh || !web {
			return "", invalidResponse()
		}
		j.mu.Lock()
		for i := range j.cookies {
			c := &j.cookies[i]
			if c.Name == name && domainMatches(host, c.Domain) {
				exp := meta.Exp
				c.Expires = &exp
			}
		}
		j.mu.Unlock()
		return pair[1], nil
	}
	return "", invalidResponse()
}

var transferHosts = map[string]bool{"steamcommunity.com": true, "store.steampowered.com": true, "help.steampowered.com": true, "checkout.steampowered.com": true, "steam.tv": true}

func sessionCookies(ctx context.Context, c *Context, _ map[string]any) (any, error) {
	s, e := activeSession(c)
	if e != nil {
		return nil, e
	}
	if e = LoadCookies(c.Transport, c.State); e != nil {
		return nil, e
	}
	j := c.Transport.Jar.(*trackingJar)
	defer SaveCookies(c.Transport, c.State)
	if textValue(s["session_id"]) == "" {
		s["session_id"] = randomHandle()[:24]
	}
	if s["platform"] == "mobile" {
		if number(s["access_expires_at"]) <= timestamp() {
			if _, e = sessionRefresh(ctx, c, map[string]any{}); e != nil {
				return nil, e
			}
		}
		for host := range transferHosts {
			expiry := number(s["access_expires_at"])
			putCookie(j, "steamLoginSecure", encodeCookie(textValue(s["steam_id"])+"||"+textValue(s["access_token"])), host, &expiry)
			putCookie(j, "sessionid", textValue(s["session_id"]), host, nil)
		}
	} else {
		seedCookies(j, s)
		fields := map[string]string{"nonce": textValue(s["refresh_token"]), "sessionid": textValue(s["session_id"]), "redir": "https://steamcommunity.com/login/home/?goto="}
		b, ct, e := multipartFields(fields)
		if e != nil {
			return nil, e
		}
		r, e := c.Transport.Request(ctx, "POST", "https://login.steampowered.com/jwt/finalizelogin", http.Header{"Origin": []string{"https://steamcommunity.com"}, "Referer": []string{"https://steamcommunity.com/"}}, b, ct)
		if e != nil {
			return nil, e
		}
		if r.Status >= 400 {
			return nil, fail(502, "upstream_login_failed")
		}
		var data map[string]any
		if json.Unmarshal(r.Body, &data) != nil || data == nil || data["error"] != nil {
			return nil, invalidResponse()
		}
		transfers, ok := data["transfer_info"].([]any)
		if data["steamID"] != s["steam_id"] || !ok || len(transfers) == 0 || len(transfers) > 10 {
			return nil, invalidResponse()
		}
		type transfer struct {
			u      *url.URL
			fields map[string]string
		}
		validated := []transfer{}
		for _, v := range transfers {
			d := object(v)
			raw := textValue(d["url"])
			if raw == "" {
				return nil, invalidResponse()
			}
			u, e := validateURL(raw)
			if e != nil {
				return nil, e
			}
			if !transferHosts[u.Hostname()] {
				return nil, fail(400, "egress_denied")
			}
			params := object(d["params"])
			if params == nil {
				return nil, invalidResponse()
			}
			f := map[string]string{}
			for k, v := range params {
				value, ok := v.(string)
				if !ok || len(k) > 128 || len(value) > 16384 {
					return nil, invalidResponse()
				}
				f[k] = value
			}
			f["steamID"] = textValue(s["steam_id"])
			validated = append(validated, transfer{u, f})
		}
		for _, v := range validated {
			b, ct, e := multipartFields(v.fields)
			if e != nil {
				return nil, e
			}
			r, e := c.Transport.Request(ctx, "POST", v.u.String(), nil, b, ct)
			if e != nil {
				return nil, e
			}
			if r.Status >= 400 {
				return nil, fail(502, "upstream_login_failed")
			}
			access, e := cookieToken(j, v.u.Hostname(), "steamLoginSecure", s, false)
			if e != nil {
				return nil, e
			}
			if v.u.Hostname() == "steamcommunity.com" {
				s["access_token"] = access
				claims, _ := jwtClaims(access)
				s["access_expires_at"] = claims.Exp
			}
			putCookie(j, "sessionid", textValue(s["session_id"]), v.u.Hostname(), nil)
		}
		rotated, e := cookieToken(j, "login.steampowered.com", "steamRefresh_steam", s, true)
		if e != nil {
			return nil, e
		}
		claims, _ := jwtClaims(rotated)
		s["refresh_token"] = rotated
		s["refresh_expires_at"] = claims.Exp
	}
	s["ready_for_web"] = true
	return map[string]any{"status": "authenticated", "steam_id": s["steam_id"], "ready_for_web": true}, nil
}
func sessionRefresh(ctx context.Context, c *Context, args map[string]any) (any, error) {
	s, e := activeSession(c)
	if e != nil {
		return nil, e
	}
	if s["platform"] == "mobile" {
		w := new(ProtoWriter).String(1, textValue(s["refresh_token"])).Fixed64(2, decimal(s["steam_id"]))
		w.Bool(3, args["renew_refresh_token"] == true)
		m, e := authService(ctx, c, "GenerateAccessTokenForApp", w, "")
		if e != nil {
			return nil, e
		}
		access := protoString(m, 1)
		if access == "" {
			return nil, invalidResponse()
		}
		refresh := protoString(m, 2)
		if refresh == "" {
			refresh = textValue(s["refresh_token"])
		}
		meta, e := tokenMetadata(access, refresh, "mobile", textValue(s["steam_id"]))
		if e != nil {
			return nil, e
		}
		for k, v := range meta {
			s[k] = v
		}
		s["access_token"] = access
		s["refresh_token"] = refresh
		s["cookies"] = []any{}
		s["ready_for_web"] = false
	} else {
		if args["renew_refresh_token"] == true {
			return nil, fail(400, "web_refresh_renewal_unsupported")
		}
		if e := LoadCookies(c.Transport, c.State); e != nil {
			return nil, e
		}
		defer SaveCookies(c.Transport, c.State)
		j := c.Transport.Jar.(*trackingJar)
		seedCookies(j, s)
		r, e := c.Transport.Request(ctx, "GET", "https://login.steampowered.com/jwt/refresh?redir=https%3A%2F%2Fsteamcommunity.com", nil, nil, "")
		if e != nil {
			return nil, e
		}
		if r.Status >= 400 {
			return nil, fail(502, "upstream_login_failed")
		}
		access, e := cookieToken(j, "steamcommunity.com", "steamLoginSecure", s, false)
		if e != nil {
			return nil, e
		}
		a, _ := jwtClaims(access)
		s["access_token"] = access
		s["access_expires_at"] = a.Exp
		refresh, e := cookieToken(j, "login.steampowered.com", "steamRefresh_steam", s, true)
		if e != nil {
			return nil, e
		}
		rclaims, _ := jwtClaims(refresh)
		s["refresh_token"] = refresh
		s["refresh_expires_at"] = rclaims.Exp
	}
	return map[string]any{"status": "authenticated", "steam_id": s["steam_id"]}, nil
}
func sessionStatus(_ context.Context, c *Context, _ map[string]any) (any, error) {
	s, p, g := object(c.State["session"]), object(c.State["pending_login"]), object(c.State["guard"])
	pending := textValue(p["client_id"]) != "" && textValue(p["request_id"]) != "" && number(p["expires_at"]) > timestamp()
	auth := textValue(s["refresh_token"]) != "" && number(s["refresh_expires_at"]) > timestamp()
	out := map[string]any{"status": "unauthenticated", "steam_id": nil, "expires_at": nil, "login_handle": nil, "challenge_url": nil, "poll_interval": nil, "guard_configured": textValue(g["shared_secret"]) != "" || textValue(g["identity_secret"]) != "", "ready_for_web": false}
	if pending {
		out["status"] = "pending"
		out["expires_at"] = p["expires_at"]
		out["login_handle"] = p["login_handle"]
		out["challenge_url"] = p["challenge_url"]
		out["poll_interval"] = p["poll_interval"]
	}
	if auth {
		out["status"] = "authenticated"
		out["steam_id"] = s["steam_id"]
		out["expires_at"] = s["access_expires_at"]
		temp := NewTransport()
		if e := LoadCookies(temp, c.State); e != nil {
			return nil, e
		}
		u, _ := url.Parse("https://steamcommunity.com/")
		for _, cookie := range temp.Jar.Cookies(u) {
			if cookie.Name == "steamLoginSecure" {
				out["ready_for_web"] = true
			}
		}
	}
	return out, nil
}
func configureGuard(_ context.Context, c *Context, args map[string]any) (any, error) {
	if args["clear"] == true {
		delete(c.State, "guard")
		return map[string]any{"configured": false}, nil
	}
	g := map[string]any{}
	for k, v := range object(c.State["guard"]) {
		g[k] = v
	}
	for _, k := range []string{"shared_secret", "identity_secret"} {
		if v, ok := args[k]; ok {
			s := textValue(v)
			b, e := base64.StdEncoding.DecodeString(s)
			if len(s) != 28 || !strings.HasSuffix(s, "=") || e != nil || len(b) != 20 {
				return nil, fail(400, "invalid_arguments")
			}
			g[k] = s
		}
	}
	for _, k := range []string{"device_id", "revocation_code"} {
		if v, ok := args[k]; ok {
			g[k] = v
		}
	}
	c.State["guard"] = g
	return map[string]any{"configured": textValue(g["shared_secret"]) != "" || textValue(g["identity_secret"]) != ""}, nil
}
func SessionOperations() []Operation {
	enum := func(v ...string) map[string]any { return map[string]any{"type": "string", "enum": v} }
	handle := map[string]any{"login_handle": strSchema(128)}
	spec := func(name string, props map[string]any, required []string, run func(context.Context, *Context, map[string]any) (any, error)) Operation {
		return Operation{Name: name, Scope: "admin", Mutating: name != "session.status", Description: "Bounded Steam session transition; sensitive material remains encrypted.", Schema: schema(props, required), Run: func(ctx context.Context, c *Context, a map[string]any) (any, error) {
			if c.Scope != "admin" {
				return nil, fail(403, "scope_denied")
			}
			if e := ValidateArgs(Operation{Schema: schema(props, required)}, a); e != nil {
				return nil, e
			}
			return run(ctx, c, a)
		}}
	}
	return []Operation{spec("session.credentials", map[string]any{"account_name": strSchema(128), "password": strSchema(1024), "platform": enum("web", "mobile"), "persistence": map[string]any{"type": "boolean"}, "device_friendly_name": strSchema(128)}, []string{"account_name", "password"}, sessionCredentials), spec("session.qr", map[string]any{"platform": enum("web"), "device_friendly_name": strSchema(128)}, nil, sessionQR), spec("session.code", map[string]any{"login_handle": strSchema(128), "auth_code": map[string]any{"type": "string", "minLength": 5, "maxLength": 8, "pattern": "^[A-Za-z0-9]+$"}, "code_type": enum("device", "email")}, []string{"login_handle", "auth_code"}, sessionCode), spec("session.poll", handle, []string{"login_handle"}, sessionPoll), spec("session.cookies", map[string]any{}, nil, sessionCookies), spec("session.refresh", map[string]any{"renew_refresh_token": map[string]any{"type": "boolean"}}, nil, sessionRefresh), spec("session.cancel", handle, []string{"login_handle"}, func(_ context.Context, c *Context, a map[string]any) (any, error) {
		if _, e := pendingLogin(c, a, false); e != nil {
			return nil, e
		}
		delete(c.State, "pending_login")
		return map[string]any{"status": "cancelled"}, nil
	}), spec("session.status", map[string]any{}, nil, sessionStatus), spec("guard.configure", map[string]any{"shared_secret": strSchema(128), "identity_secret": strSchema(128), "device_id": map[string]any{"type": "string", "maxLength": 128, "pattern": "^android:[0-9a-f-]{36}$"}, "revocation_code": strSchema(128), "clear": map[string]any{"type": "boolean"}}, nil, configureGuard), spec("guard.enroll", map[string]any{}, nil, guardEnrollPhase1), spec("guard.finalize", map[string]any{"activation_code": map[string]any{"type": "string", "minLength": 5, "maxLength": 16, "pattern": "^[A-Za-z0-9]+$"}}, nil, guardEnrollFinalize)}
}
