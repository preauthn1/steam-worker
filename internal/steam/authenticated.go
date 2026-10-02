package steam

// Authenticated inventory, market, trade and mobile-confirmation protocol operations.
// Monetary writes require an explicit currency matching a successful wallet refresh.
// Each mutation is sent once, without automatic confirmation approval or retries.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const authCommunity = "https://steamcommunity.com"
const authMarket = authCommunity + "/market"
const authMaxInt int64 = 9007199254740991

type authSession struct{ steamID, token, sessionID string }
type authRequestOptions struct{ meta, multipart, pending406 bool }
type authRunner func(context.Context, *Context, map[string]any, authSession) (any, error)

func authErr(status int, code string) error { return &APIError{Status: status, Code: code} }
func authInvalid() error                    { return authErr(400, "invalid_arguments") }
func authMalformed() error                  { return authErr(502, "malformed_upstream_response") }
func authObject(v any) (map[string]any, error) {
	switch m := v.(type) {
	case map[string]any:
		if m != nil {
			return m, nil
		}
	case State:
		if m != nil {
			return map[string]any(m), nil
		}
	}
	return nil, authMalformed()
}
func authNumber(v any, min, max int64) (int64, error) {
	if v == nil {
		return 0, authInvalid()
	}
	r := reflect.ValueOf(v)
	var n int64
	switch r.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n = r.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u := r.Uint()
		if u > uint64(authMaxInt) {
			return 0, authInvalid()
		}
		n = int64(u)
	case reflect.Float32, reflect.Float64:
		f := r.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || f < float64(min) || f > float64(max) || math.Abs(f) > float64(authMaxInt) {
			return 0, authInvalid()
		}
		n = int64(f)
	default:
		return 0, authInvalid()
	}
	if n < min || n > max || n > authMaxInt {
		return 0, authInvalid()
	}
	return n, nil
}
func authID(v any) (string, error) {
	s, ok := v.(string)
	if !ok || !regexp.MustCompile(`^[1-9][0-9]{0,19}$`).MatchString(s) {
		return "", authInvalid()
	}
	if _, e := strconv.ParseUint(s, 10, 64); e != nil {
		return "", authInvalid()
	}
	return s, nil
}
func authSteamID(v any) (string, error) {
	s, e := authID(v)
	if e != nil {
		return "", e
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	if n < 76561197960265729 || n > 76561202255233023 {
		return "", authInvalid()
	}
	return s, nil
}
func authText(v any, max int, empty bool) (string, error) {
	s, ok := v.(string)
	if !ok || (!empty && s == "") || len(utf16.Encode([]rune(s))) > max {
		return "", authInvalid()
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return "", authInvalid()
		}
	}
	return s, nil
}
func authUpID(v any) (string, error) {
	s, e := authID(v)
	if e != nil {
		return "", authMalformed()
	}
	return s, nil
}
func authFlag(v any) (bool, error) {
	if v == nil {
		return false, nil
	}
	if b, ok := v.(bool); ok {
		return b, nil
	}
	n, e := authNumber(v, 0, 1)
	if e != nil {
		return false, authMalformed()
	}
	return n == 1, nil
}
func authSuccess(m map[string]any) error {
	v, ok := m["success"]
	if !ok {
		return authErr(502, "upstream_rejected")
	}
	b, e := authFlag(v)
	if e != nil || !b {
		return authErr(502, "upstream_rejected")
	}
	return nil
}
func authPending(m map[string]any) (bool, error) {
	out := false
	for _, k := range []string{"needs_mobile_confirmation", "needs_email_confirmation", "need_confirmation"} {
		b, e := authFlag(m[k])
		if e != nil {
			return false, e
		}
		out = out || b
	}
	return out, nil
}
func authResult(m map[string]any) (any, error) {
	mobile, e := authFlag(m["needs_mobile_confirmation"])
	if e != nil {
		return nil, e
	}
	need, e := authFlag(m["need_confirmation"])
	if e != nil {
		return nil, e
	}
	email, e := authFlag(m["needs_email_confirmation"])
	if e != nil {
		return nil, e
	}
	if need && m["confirmation"] != nil {
		c, e := authObject(m["confirmation"])
		if e != nil {
			return nil, e
		}
		if _, e = authUpID(c["confirmation_id"]); e != nil {
			return nil, e
		}
	}
	m["pending_confirmation"] = mobile || need || email
	m["needs_mobile_confirmation"] = mobile || need
	m["needs_email_confirmation"] = email
	return m, nil
}
func authSlice(v any) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	r := reflect.ValueOf(v)
	if r.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, r.Len())
	for i := range out {
		out[i] = r.Index(i).Interface()
	}
	return out, true
}
func authReadSession(c *Context) (authSession, error) {
	var s authSession
	if c == nil || c.Transport == nil || c.State == nil {
		return s, authErr(401, "authentication_required")
	}
	m, e := authObject(c.State["session"])
	if e != nil {
		return s, authErr(401, "authentication_required")
	}
	s.steamID, e = authSteamID(m["steam_id"])
	if e != nil {
		return s, authErr(401, "authentication_required")
	}
	s.token, e = authText(m["access_token"], 8192, false)
	if e != nil {
		return s, authErr(401, "authentication_required")
	}
	s.sessionID, e = authText(m["session_id"], 256, false)
	if e != nil {
		return s, authErr(401, "authentication_required")
	}
	cookies, ok := authSlice(m["cookies"])
	if !ok {
		return s, authErr(401, "authentication_required")
	}
	for _, v := range cookies {
		record, er := authObject(v)
		if er != nil {
			return s, authErr(401, "authentication_required")
		}
		for _, key := range []string{"name", "value", "domain", "path"} {
			if _, ok := record[key].(string); !ok {
				return s, authErr(401, "authentication_required")
			}
		}
		for _, key := range []string{"hostOnly", "secure"} {
			if _, ok := record[key].(bool); !ok {
				return s, authErr(401, "authentication_required")
			}
		}
		expires, present := record["expires"]
		if !present {
			return s, authErr(401, "authentication_required")
		}
		if expires != nil {
			r := reflect.ValueOf(expires)
			if r.Kind() != reflect.Float64 && r.Kind() != reflect.Float32 && r.Kind() != reflect.Int && r.Kind() != reflect.Int64 {
				return s, authErr(401, "authentication_required")
			}
			f := float64(0)
			if r.Kind() == reflect.Float64 || r.Kind() == reflect.Float32 {
				f = r.Float()
			} else {
				f = float64(r.Int())
			}
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return s, authErr(401, "authentication_required")
			}
		}
	}
	if e = LoadCookies(c.Transport, c.State); e != nil || c.Transport.Jar == nil {
		return s, authErr(401, "authentication_required")
	}
	u, _ := url.Parse(authCommunity + "/")
	entries := map[string]string{}
	for _, cookie := range c.Transport.Jar.Cookies(u) {
		if strings.ContainsAny(cookie.Name+cookie.Value, "\r\n") {
			return s, authErr(401, "authentication_required")
		}
		entries[cookie.Name] = cookie.Value
	}
	if entries["steamLoginSecure"] == "" || entries["sessionid"] != s.sessionID {
		return s, authErr(401, "authentication_required")
	}
	return s, nil
}

// Go's fmt prints large float64 integers in exponent notation; Steam forms require decimal integers.
func authWire(v any) string {
	if n, e := authNumber(v, 0, authMaxInt); e == nil {
		return strconv.FormatInt(n, 10)
	}
	return fmt.Sprint(v)
}
func authParams(kv ...any) url.Values {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i].(string), authWire(kv[i+1]))
	}
	return v
}
func authDefault(a map[string]any, k string, v any) any {
	if x, ok := a[k]; ok {
		return x
	}
	return v
}
func authHTTP(ctx context.Context, c *Context, method, target string, p url.Values, referer string, o authRequestOptions) (*Response, error) {
	u, e := url.Parse(target)
	if e != nil {
		return nil, authInvalid()
	}
	h := http.Header{"Accept": []string{"application/json"}, "Referer": []string{referer}}
	var body []byte
	ct := ""
	if method == http.MethodGet {
		u.RawQuery = p.Encode()
	} else if o.multipart {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for k, vs := range p {
			for _, v := range vs {
				if e = w.WriteField(k, v); e != nil {
					return nil, authInvalid()
				}
			}
		}
		if e = w.Close(); e != nil {
			return nil, authInvalid()
		}
		body = b.Bytes()
		ct = w.FormDataContentType()
	} else {
		body = []byte(p.Encode())
		ct = "application/x-www-form-urlencoded"
	}
	r, e := c.Transport.Request(ctx, method, u.String(), h, body, ct)
	if e != nil {
		return nil, e
	}
	if r.Status == 429 {
		return nil, authErr(429, "upstream_rate_limited")
	}
	if r.Status == 401 || r.Status == 403 {
		return nil, authErr(401, "authentication_required")
	}
	ru, e := url.Parse(r.URL)
	if e != nil || ru.Hostname() != u.Hostname() || regexp.MustCompile(`/(login|openid)(/|$)`).MatchString(ru.Path) {
		return nil, authErr(401, "authentication_required")
	}
	if (r.Status < 200 || r.Status >= 300) && !(o.pending406 && r.Status == 406) {
		return nil, authErr(502, "upstream_http_error")
	}
	if er := r.Headers.Get("X-Eresult"); er != "" && er != "1" {
		return nil, authErr(502, "upstream_rejected")
	}
	return r, nil
}
func authRequest(ctx context.Context, c *Context, method, target string, p url.Values, referer string, o authRequestOptions) (map[string]any, error) {
	r, e := authHTTP(ctx, c, method, target, p, referer, o)
	if e != nil {
		return nil, e
	}
	if o.meta && len(r.Body) == 0 {
		return map[string]any{"upstream_status": r.Status, "pending_confirmation": false}, nil
	}
	var m map[string]any
	if e = json.Unmarshal(r.Body, &m); e != nil || m == nil {
		return nil, authMalformed()
	}
	for _, key := range []string{"needauth", "needs_mobile_confirmation", "needs_email_confirmation", "need_confirmation", "more_items", "active", "purchased"} {
		if value, exists := m[key]; exists {
			if value == nil {
				return nil, authMalformed()
			}
			if _, err := authFlag(value); err != nil {
				return nil, err
			}
		}
	}
	need, e := authFlag(m["needauth"])
	if e != nil {
		return nil, e
	}
	if need {
		return nil, authErr(401, "authentication_required")
	}
	if authTruthy(m["error"]) || authTruthy(m["strError"]) {
		return nil, authErr(502, "upstream_rejected")
	}
	if r.Status == 406 {
		b, e := authFlag(m["need_confirmation"])
		if e != nil || !b {
			return nil, authMalformed()
		}
	}
	if o.meta {
		if e = authSuccess(m); e != nil {
			return nil, e
		}
	}
	return m, nil
}
func authTruthy(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	}
	return true
}
func authNumSchema(min, max int64) map[string]any {
	return map[string]any{"type": "integer", "minimum": min, "maximum": max}
}
func authIDSchema() map[string]any {
	return map[string]any{"type": "string", "format": "uint64", "pattern": "^[1-9][0-9]{0,19}$", "maxLength": 20}
}
func authStringSchema(min, max int) map[string]any {
	return map[string]any{"type": "string", "minLength": min, "maxLength": max}
}
func authValidate(v any, s map[string]any) error {
	switch s["type"] {
	case "integer":
		_, e := authNumber(v, s["minimum"].(int64), s["maximum"].(int64))
		return e
	case "string":
		min := 0
		max := 500
		if x, ok := s["minLength"].(int); ok {
			min = x
		}
		if x, ok := s["maxLength"].(int); ok {
			max = x
		}
		str, e := authText(v, max, min == 0)
		if e != nil || len(utf16.Encode([]rune(str))) < min {
			return authInvalid()
		}
		if p, ok := s["pattern"].(string); ok {
			if !regexp.MustCompile(p).MatchString(str) {
				return authInvalid()
			}
			if p == "^[1-9][0-9]{0,19}$" {
				_, e = authID(str)
				return e
			}
		}
		return nil
	case "boolean":
		if _, ok := v.(bool); !ok {
			return authInvalid()
		}
		return nil
	case "object":
		m, e := authObject(v)
		if e != nil {
			return authInvalid()
		}
		return authCheck(m, s["properties"].(map[string]any), s["required"].([]string))
	case "array":
		a, ok := authSlice(v)
		if !ok {
			return authInvalid()
		}
		min := 0
		max := 500
		if n, ok := s["minItems"].(int); ok {
			min = n
		}
		if n, ok := s["maxItems"].(int); ok {
			max = n
		}
		if len(a) < min || len(a) > max {
			return authInvalid()
		}
		seen := map[string]bool{}
		for _, x := range a {
			if e := authValidate(x, s["items"].(map[string]any)); e != nil {
				return e
			}
			if s["uniqueItems"] == true {
				b, _ := json.Marshal(x)
				if seen[string(b)] {
					return authInvalid()
				}
				seen[string(b)] = true
			}
		}
		return nil
	}
	return authInvalid()
}
func authCheck(a map[string]any, p map[string]any, req []string) error {
	for _, k := range req {
		if _, ok := a[k]; !ok {
			return authInvalid()
		}
	}
	for k, v := range a {
		s, ok := p[k]
		if !ok {
			return authInvalid()
		}
		if e := authValidate(v, s.(map[string]any)); e != nil {
			return e
		}
	}
	return nil
}
func authOp(name, scope string, p map[string]any, required []string, description string, run authRunner) Operation {
	if required == nil {
		required = []string{}
	}
	return Operation{Name: name, Scope: scope, Mutating: scope != "read", Description: description, Schema: map[string]any{"type": "object", "additionalProperties": false, "properties": p, "required": required}, Run: func(ctx context.Context, c *Context, a map[string]any) (any, error) {
		s, e := authReadSession(c)
		if e != nil {
			return nil, e
		}
		defer SaveCookies(c.Transport, c.State)
		if (scope == "admin" && c.Scope != "admin") || (scope == "write" && c.Scope != "write" && c.Scope != "admin") {
			return nil, authErr(403, "insufficient_scope")
		}
		if e = authCheck(a, p, required); e != nil {
			return nil, e
		}
		return run(ctx, c, a, s)
	}}
}
func authCurrency(a map[string]any, c *Context) (int64, error) {
	n, e := authNumber(a["currency"], 1, 47)
	if e != nil {
		return 0, e
	}
	w, e := authObject(c.State["wallet"])
	if e != nil {
		return 0, authErr(409, "wallet_currency_required")
	}
	wn, e := authNumber(w["currency"], 0, authMaxInt)
	if e != nil {
		return 0, authErr(409, "wallet_currency_required")
	}
	if n != wn {
		return 0, authErr(400, "wallet_currency_mismatch")
	}
	return n, nil
}
func authListingReferer(a map[string]any) string {
	return authMarket + "/listings/" + authWire(a["app"]) + "/" + authURIComponent(a["market_hash_name"].(string))
}
func authURIComponent(s string) string {
	encoded := strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
	// Match JavaScript encodeURIComponent for the listing/trade referer contract.
	return strings.NewReplacer("%21", "!", "%27", "'", "%28", "(", "%29", ")", "%2A", "*").Replace(encoded)
}
func authWallet(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
	delete(c.State, "wallet")
	target := authCommunity + "/profiles/" + s.steamID + "/inventory"
	r, e := authHTTP(ctx, c, "GET", target, nil, authCommunity+"/profiles/"+s.steamID, authRequestOptions{})
	if e != nil {
		return nil, e
	}
	if r.Status != 200 {
		return nil, authErr(502, "upstream_http_error")
	}
	matches := regexp.MustCompile(`\bg_rgWalletInfo\s*=\s*(\{[^\r\n]*\})\s*;`).FindAllSubmatch(r.Body, -1)
	if len(matches) != 1 {
		return nil, authMalformed()
	}
	var w map[string]any
	if e = json.Unmarshal(matches[0][1], &w); e != nil || w == nil {
		return nil, authMalformed()
	}
	if e = authSuccess(w); e != nil {
		return nil, e
	}
	currency, e := authNumber(w["wallet_currency"], 1, 47)
	if e != nil {
		return nil, authMalformed()
	}
	country, ok := w["wallet_country"].(string)
	if !ok || !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(country) {
		return nil, authMalformed()
	}
	for _, k := range []string{"wallet_fee", "wallet_fee_minimum", "wallet_market_minimum", "wallet_currency_increment", "wallet_fee_base", "wallet_balance", "wallet_delayed_balance", "wallet_max_balance", "wallet_trade_max_balance"} {
		if str, ok := w[k].(string); ok {
			n, e := strconv.ParseUint(str, 10, 64)
			if !regexp.MustCompile(`^[0-9]+$`).MatchString(str) || e != nil || n > uint64(authMaxInt) {
				return nil, authMalformed()
			}
		} else if _, e := authNumber(w[k], 0, authMaxInt); e != nil {
			return nil, authMalformed()
		}
	}
	for _, k := range []string{"wallet_fee_percent", "wallet_publisher_fee_percent_default"} {
		var f float64
		switch v := w[k].(type) {
		case float64:
			f = v
		case string:
			if !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`).MatchString(v) {
				return nil, authMalformed()
			}
			f, e = strconv.ParseFloat(v, 64)
			if e != nil {
				return nil, authMalformed()
			}
		default:
			return nil, authMalformed()
		}
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
			return nil, authMalformed()
		}
	}
	if _, ok = w["wallet_state"].(string); !ok {
		return nil, authMalformed()
	}
	w["currency"] = currency
	w["country"] = country
	c.State["wallet"] = w
	return w, nil
}
func authInventory(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
	p := authParams("l", authDefault(a, "language", "english"), "count", authDefault(a, "count", 2000), "raw_asset_properties", 1, "preserve_bbcode", 1)
	if v, ok := a["start_asset_id"]; ok {
		p.Set("start_assetid", v.(string))
	}
	r, e := authRequest(ctx, c, "GET", authCommunity+"/inventory/"+s.steamID+"/"+authWire(a["app"])+"/"+a["context_id"].(string), p, authCommunity+"/inventory/"+s.steamID+"/", authRequestOptions{})
	if e != nil {
		return nil, e
	}
	if e = authSuccess(r); e != nil {
		return nil, e
	}
	total, e := authNumber(r["total_inventory_count"], 0, authMaxInt)
	if e != nil {
		return nil, authMalformed()
	}
	assets, hasAssets := authSlice(r["assets"])
	_, hasDesc := authSlice(r["descriptions"])
	_, assetsPresent := r["assets"]
	_, descriptionsPresent := r["descriptions"]
	if (assetsPresent && !hasAssets) || (descriptionsPresent && !hasDesc) || (total > 0 && (!hasAssets || !hasDesc)) {
		return nil, authMalformed()
	}
	if cursor, ok := r["last_assetid"]; ok {
		str, e := authUpID(cursor)
		if e != nil {
			return nil, e
		}
		if start, ok := a["start_asset_id"]; ok {
			cn, _ := strconv.ParseUint(str, 10, 64)
			sn, _ := strconv.ParseUint(start.(string), 10, 64)
			if cn <= sn {
				return nil, authMalformed()
			}
		}
	}
	more, e := authFlag(r["more_items"])
	if e != nil {
		return nil, e
	}
	if _, ok := r["last_assetid"]; more && !ok {
		return nil, authMalformed()
	}
	for _, v := range assets {
		asset, e := authObject(v)
		if e != nil {
			return nil, e
		}
		for _, k := range []string{"assetid", "contextid", "classid"} {
			if _, e = authUpID(asset[k]); e != nil {
				return nil, e
			}
		}
		amount, ok := asset["amount"].(string)
		if !ok || !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(amount) {
			return nil, authMalformed()
		}
	}
	return r, nil
}
func authEcon(ctx context.Context, c *Context, s authSession, method string, p url.Values) (map[string]any, error) {
	p.Set("access_token", s.token)
	p.Set("language", "english")
	p.Set("get_descriptions", "1")
	r, e := authRequest(ctx, c, "GET", "https://api.steampowered.com/IEconService/"+method+"/v1/", p, authCommunity, authRequestOptions{})
	if e != nil {
		return nil, e
	}
	return authObject(r["response"])
}
func authAssetSchema() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"appid": authNumSchema(1, 4294967295), "contextid": authIDSchema(), "assetid": authIDSchema(), "amount": authNumSchema(1, 4294967295)}, "required": []string{"appid", "contextid", "assetid", "amount"}}
}
func authAssets(v any) ([]map[string]any, error) {
	arr, ok := authSlice(v)
	if !ok || len(arr) > 200 {
		return nil, authInvalid()
	}
	out := make([]map[string]any, 0, len(arr))
	seen := map[string]bool{}
	for _, x := range arr {
		if e := authValidate(x, authAssetSchema()); e != nil {
			return nil, e
		}
		m, _ := authObject(x)
		app, _ := authNumber(m["appid"], 1, 4294967295)
		amount, _ := authNumber(m["amount"], 1, 4294967295)
		key := fmt.Sprint(app) + ":" + m["contextid"].(string) + ":" + m["assetid"].(string)
		if seen[key] {
			return nil, authInvalid()
		}
		seen[key] = true
		out = append(out, map[string]any{"appid": app, "contextid": m["contextid"], "assetid": m["assetid"], "amount": strconv.FormatInt(amount, 10)})
	}
	return out, nil
}
func authTradeSend(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
	partner, e := authSteamID(a["partner"])
	if e != nil || partner == s.steamID {
		return nil, authInvalid()
	}
	give, e := authAssets(a["to_partner"])
	if e != nil {
		return nil, e
	}
	receive, e := authAssets(a["from_partner"])
	if e != nil {
		return nil, e
	}
	if len(give)+len(receive) == 0 {
		return nil, authInvalid()
	}
	pn, _ := strconv.ParseUint(partner, 10, 64)
	referer := authCommunity + "/tradeoffer/new/?partner=" + strconv.FormatUint(pn-76561197960265728, 10)
	create := map[string]any{}
	if token, ok := a["token"]; ok {
		referer += "&token=" + authURIComponent(token.(string))
		create["trade_offer_access_token"] = token
	}
	if counter, ok := a["countered_id"]; ok {
		referer = authCommunity + "/tradeoffer/" + counter.(string) + "/"
	}
	offer, _ := json.Marshal(map[string]any{"newversion": true, "version": len(give) + len(receive) + 1, "me": map[string]any{"assets": give, "currency": []any{}, "ready": false}, "them": map[string]any{"assets": receive, "currency": []any{}, "ready": false}})
	createJSON, _ := json.Marshal(create)
	p := authParams("sessionid", s.sessionID, "serverid", 1, "partner", partner, "tradeoffermessage", authDefault(a, "message", ""), "json_tradeoffer", string(offer), "captcha", "", "trade_offer_create_params", string(createJSON))
	if counter, ok := a["countered_id"]; ok {
		p.Set("tradeofferid_countered", counter.(string))
	}
	r, e := authRequest(ctx, c, "POST", authCommunity+"/tradeoffer/new/send", p, referer, authRequestOptions{})
	if e != nil {
		return nil, e
	}
	if v, ok := r["tradeofferid"]; ok {
		if _, e = authUpID(v); e != nil {
			return nil, e
		}
	} else {
		pending, e := authPending(r)
		if e != nil {
			return nil, e
		}
		if !pending {
			return nil, authMalformed()
		}
	}
	return authResult(r)
}
func authConfirmationParams(c *Context, s authSession, tag string) (url.Values, error) {
	g, e := authObject(c.State["guard"])
	if e != nil {
		return nil, authErr(401, "guard_required")
	}
	secret, ok := g["identity_secret"].(string)
	device, ok2 := g["device_id"].(string)
	if !ok || !ok2 || len(secret) < 16 || !regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`).MatchString(secret) || !regexp.MustCompile(`^android:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(device) {
		return nil, authErr(401, "guard_required")
	}
	if _, e = base64.StdEncoding.DecodeString(secret); e != nil {
		return nil, authErr(401, "guard_required")
	}
	t := time.Now().Unix()
	key, e := GenerateConfirmationKey(secret, tag, t)
	if e != nil {
		return nil, authErr(401, "guard_required")
	}
	return authParams("p", device, "a", s.steamID, "k", key, "t", t, "m", "react", "tag", tag), nil
}
func authConfirmations(ctx context.Context, c *Context, s authSession) ([]map[string]any, error) {
	p, e := authConfirmationParams(c, s, "getlist")
	if e != nil {
		return nil, e
	}
	r, e := authRequest(ctx, c, "GET", authCommunity+"/mobileconf/getlist", p, authCommunity, authRequestOptions{})
	if e != nil {
		return nil, e
	}
	if e = authSuccess(r); e != nil {
		return nil, e
	}
	arr, ok := authSlice(r["conf"])
	if !ok {
		return nil, authMalformed()
	}
	out := make([]map[string]any, 0, len(arr))
	seen := map[string]bool{}
	for _, v := range arr {
		m, e := authObject(v)
		if e != nil {
			return nil, e
		}
		id, e := authUpID(m["id"])
		if e != nil {
			return nil, e
		}
		if _, e = authUpID(m["nonce"]); e != nil {
			return nil, e
		}
		if seen[id] {
			return nil, authMalformed()
		}
		seen[id] = true
		if _, e = authNumber(m["type"], 0, 13); e != nil {
			return nil, authErr(502, "unknown_confirmation_type")
		}
		out = append(out, m)
	}
	return out, nil
}
func authConfirmWrite(ctx context.Context, c *Context, a map[string]any, s authSession, mode string) (any, error) {
	bulk := mode != "accept" && mode != "deny"
	if bulk && c.Scope != "admin" {
		return nil, authErr(403, "insufficient_scope")
	}
	var ids []string
	if !bulk {
		ids = []string{a["confirmation_id"].(string)}
	} else if mode == "multiple" {
		arr, _ := authSlice(a["confirmation_ids"])
		for _, v := range arr {
			ids = append(ids, v.(string))
		}
	}
	all, e := authConfirmations(ctx, c, s)
	if e != nil {
		return nil, e
	}
	selected := all
	if ids != nil {
		selected = make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			found := false
			for _, m := range all {
				if m["id"] == id {
					selected = append(selected, m)
					found = true
					break
				}
			}
			if !found {
				return nil, authErr(404, "confirmation_not_found")
			}
		}
	}
	for _, m := range selected {
		n, _ := authNumber(m["type"], 0, 13)
		if n != 2 && n != 3 && n != 12 && n != 13 {
			return nil, authErr(403, "confirmation_type_denied")
		}
	}
	if len(selected) > 200 {
		return nil, authErr(400, "confirmation_batch_too_large")
	}
	processed := []string{}
	if len(selected) == 0 {
		return map[string]any{"success": true, "processed_ids": processed}, nil
	}
	tag := "cancel"
	if mode == "accept" || mode == "accept_all" || (mode == "multiple" && a["accept"] == true) {
		tag = "allow"
	}
	p, e := authConfirmationParams(c, s, tag)
	if e != nil {
		return nil, e
	}
	p.Set("op", tag)
	cid, ck := "cid", "ck"
	method, path := "GET", "ajaxop"
	if bulk {
		cid, ck = "cid[]", "ck[]"
		method, path = "POST", "multiajaxop"
	}
	for _, m := range selected {
		p.Add(cid, m["id"].(string))
		p.Add(ck, m["nonce"].(string))
		processed = append(processed, m["id"].(string))
	}
	r, e := authRequest(ctx, c, method, authCommunity+"/mobileconf/"+path, p, authCommunity, authRequestOptions{})
	if e != nil {
		return nil, e
	}
	if e = authSuccess(r); e != nil {
		return nil, e
	}
	return map[string]any{"success": true, "processed_ids": processed}, nil
}

// AuthenticatedOperations returns the 21 concrete authenticated protocol operations.
func AuthenticatedOperations() []Operation {
	id := authIDSchema
	num := func(min int64) map[string]any { return authNumSchema(min, authMaxInt) }
	app := authNumSchema(1, 4294967295)
	currency := authNumSchema(1, 47)
	str := authStringSchema(1, 500)
	boolean := map[string]any{"type": "boolean"}
	steamID := id()
	steamID["minLength"] = 17
	steamID["maxLength"] = 17
	assetList := map[string]any{"type": "array", "maxItems": 200, "items": authAssetSchema(), "uniqueItems": true}
	ops := []Operation{
		authOp("wallet.info", "read", map[string]any{}, nil, "Read authenticated inventory-page wallet info and persist trusted currency; required before monetary writes.", authWallet),
		authOp("inventory.get", "read", map[string]any{"app": app, "context_id": id(), "start_asset_id": id(), "count": authNumSchema(1, 2000), "language": str}, []string{"app", "context_id"}, "Get a page of authenticated inventory.", authInventory),
		authOp("market.get_user_listings", "read", map[string]any{"start": num(0), "count": authNumSchema(1, 100)}, nil, "Get active sell listings, pending listings and buy orders.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			r, e := authRequest(ctx, c, "GET", authMarket+"/mylistings", authParams("norender", 1, "start", authDefault(a, "start", 0), "count", authDefault(a, "count", 100)), authCommunity, authRequestOptions{})
			if e != nil {
				return nil, e
			}
			if e = authSuccess(r); e != nil {
				return nil, e
			}
			for _, k := range []string{"listings", "listings_to_confirm", "buy_orders"} {
				if _, ok := authSlice(r[k]); !ok {
					return nil, authMalformed()
				}
			}
			if _, e = authNumber(r["num_active_listings"], 0, authMaxInt); e != nil {
				return nil, authMalformed()
			}
			return r, nil
		}),
		authOp("market.place_sell_listing", "write", map[string]any{"app": app, "context_id": id(), "asset_id": id(), "to_receive": num(1), "currency": currency}, []string{"app", "context_id", "asset_id", "to_receive", "currency"}, "Sell one asset for explicit minor units in trusted wallet currency; never auto-confirm.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			if _, e := authCurrency(a, c); e != nil {
				return nil, e
			}
			r, e := authRequest(ctx, c, "POST", authMarket+"/sellitem/", authParams("sessionid", s.sessionID, "appid", a["app"], "contextid", a["context_id"], "assetid", a["asset_id"], "amount", 1, "price", a["to_receive"]), authCommunity+"/profiles/"+s.steamID+"/inventory", authRequestOptions{})
			if e != nil {
				return nil, e
			}
			if e = authSuccess(r); e != nil {
				return nil, e
			}
			return authResult(r)
		}),
		authOp("market.cancel_sell_listing", "write", map[string]any{"listing_id": id()}, []string{"listing_id"}, "Cancel a sell listing once.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			return authRequest(ctx, c, "POST", authMarket+"/removelisting/"+a["listing_id"].(string), authParams("sessionid", s.sessionID), authMarket, authRequestOptions{meta: true})
		}),
		authOp("market.place_buy_order", "write", map[string]any{"app": app, "market_hash_name": str, "price": num(1), "quantity": authNumSchema(1, 1000), "currency": currency, "confirmation_id": id()}, []string{"app", "market_hash_name", "price", "currency"}, "Place one buy order at explicit unit minor-unit price; no approval or retry.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			cur, e := authCurrency(a, c)
			if e != nil {
				return nil, e
			}
			price, _ := authNumber(a["price"], 1, authMaxInt)
			q, _ := authNumber(authDefault(a, "quantity", 1), 1, 1000)
			if price > authMaxInt/q {
				return nil, authInvalid()
			}
			r, e := authRequest(ctx, c, "POST", authMarket+"/createbuyorder/", authParams("sessionid", s.sessionID, "currency", cur, "appid", a["app"], "market_hash_name", a["market_hash_name"], "price_total", price*q, "quantity", q, "confirmation", authDefault(a, "confirmation_id", 0)), authListingReferer(a), authRequestOptions{pending406: true})
			if e != nil {
				return nil, e
			}
			pending, e := authPending(r)
			if e != nil {
				return nil, e
			}
			if !pending {
				if e = authSuccess(r); e != nil {
					return nil, e
				}
				if _, e = authUpID(r["buy_orderid"]); e != nil {
					return nil, e
				}
			} else if !authTruthy(r["confirmation"]) {
				return nil, authMalformed()
			}
			return authResult(r)
		}),
		authOp("market.cancel_buy_order", "write", map[string]any{"buy_order_id": id()}, []string{"buy_order_id"}, "Cancel one buy order.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			return authRequest(ctx, c, "POST", authMarket+"/cancelbuyorder/", authParams("sessionid", s.sessionID, "buy_orderid", a["buy_order_id"]), authMarket, authRequestOptions{meta: true})
		}),
		authOp("market.buy_listing", "write", map[string]any{"listing_id": id(), "app": app, "market_hash_name": str, "subtotal": num(1), "fee": num(0), "currency": currency, "confirmation_id": id()}, []string{"listing_id", "app", "market_hash_name", "subtotal", "fee", "currency"}, "Purchase once using explicit minor-unit subtotal, fee and currency; no fee guessing or approval.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			cur, e := authCurrency(a, c)
			if e != nil {
				return nil, e
			}
			subtotal, _ := authNumber(a["subtotal"], 1, authMaxInt)
			fee, _ := authNumber(a["fee"], 0, authMaxInt)
			if subtotal > authMaxInt-fee {
				return nil, authInvalid()
			}
			r, e := authRequest(ctx, c, "POST", authMarket+"/buylisting/"+a["listing_id"].(string), authParams("sessionid", s.sessionID, "currency", cur, "subtotal", subtotal, "fee", fee, "total", subtotal+fee, "quantity", 1, "confirmation", authDefault(a, "confirmation_id", 0)), authListingReferer(a), authRequestOptions{multipart: true, pending406: true})
			if e != nil {
				return nil, e
			}
			pending, e := authPending(r)
			if e != nil {
				return nil, e
			}
			if !pending {
				w, e := authObject(r["wallet_info"])
				if e != nil {
					return nil, e
				}
				if e = authSuccess(w); e != nil {
					return nil, e
				}
			} else if !authTruthy(r["confirmation"]) {
				return nil, authMalformed()
			}
			return authResult(r)
		}),
		authOp("market.get_buy_order_status", "read", map[string]any{"buy_order_id": id()}, []string{"buy_order_id"}, "Read order status without repeating or confirming.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			r, e := authRequest(ctx, c, "GET", authMarket+"/getbuyorderstatus/", authParams("sessionid", s.sessionID, "buy_orderid", a["buy_order_id"]), authMarket, authRequestOptions{pending406: true})
			if e != nil {
				return nil, e
			}
			pending, e := authPending(r)
			if e != nil {
				return nil, e
			}
			if !pending {
				if e = authSuccess(r); e != nil {
					return nil, e
				}
				for _, k := range []string{"active", "purchased"} {
					if _, ok := r[k]; !ok {
						return nil, authMalformed()
					}
					if _, e = authFlag(r[k]); e != nil {
						return nil, e
					}
				}
				for _, k := range []string{"quantity", "quantity_remaining"} {
					if _, e = authNumber(r[k], 0, authMaxInt); e != nil {
						return nil, authMalformed()
					}
				}
			}
			return authResult(r)
		}),
		authOp("trade.get", "read", map[string]any{"trade_offer_id": id()}, []string{"trade_offer_id"}, "Read authenticated IEconService trade offer.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			r, e := authEcon(ctx, c, s, "GetTradeOffer", authParams("tradeofferid", a["trade_offer_id"]))
			if e != nil {
				return nil, e
			}
			offer, e := authObject(r["offer"])
			if e != nil {
				return nil, e
			}
			oid, e := authUpID(offer["tradeofferid"])
			if e != nil || oid != a["trade_offer_id"] {
				return nil, authMalformed()
			}
			return r, nil
		}),
		authOp("trade.get_multiple", "read", map[string]any{"active_only": boolean, "historical_only": boolean, "historical_cutoff": num(0), "sent": boolean, "received": boolean, "cursor": num(0)}, nil, "Read sent and received offers; historical cutoff requires active_only.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			historical := a["historical_only"] == true
			active := !historical && a["active_only"] != false
			if _, ok := a["historical_cutoff"]; ok && !active {
				return nil, authInvalid()
			}
			if a["sent"] == false && a["received"] == false {
				return nil, authInvalid()
			}
			b := func(v bool) int {
				if v {
					return 1
				}
				return 0
			}
			p := authParams("active_only", b(active), "historical_only", b(historical), "get_sent_offers", b(a["sent"] != false), "get_received_offers", b(a["received"] != false), "cursor", authDefault(a, "cursor", 0))
			if cutoff, ok := a["historical_cutoff"]; ok {
				p.Set("time_historical_cutoff", authWire(cutoff))
			}
			r, e := authEcon(ctx, c, s, "GetTradeOffers", p)
			if e != nil {
				return nil, e
			}
			for _, k := range []string{"trade_offers_sent", "trade_offers_received", "descriptions"} {
				if v, ok := r[k]; ok {
					arr, ok := authSlice(v)
					if !ok {
						return nil, authMalformed()
					}
					if k != "descriptions" {
						for _, v := range arr {
							m, e := authObject(v)
							if e != nil {
								return nil, e
							}
							if _, e = authUpID(m["tradeofferid"]); e != nil {
								return nil, e
							}
						}
					}
				}
			}
			if v, ok := r["next_cursor"]; ok {
				if _, e = authNumber(v, 0, authMaxInt); e != nil {
					return nil, authMalformed()
				}
			}
			return r, nil
		}),
	}
	token := authStringSchema(1, 128)
	token["pattern"] = "^[A-Za-z0-9_-]+$"
	ops = append(ops, authOp("trade.send", "write", map[string]any{"partner": steamID, "to_partner": assetList, "from_partner": assetList, "message": authStringSchema(0, 1000), "token": token, "countered_id": id()}, []string{"partner", "to_partner", "from_partner"}, "Send one validated trade offer; never automatically confirm.", authTradeSend))
	for _, action := range []string{"accept", "decline", "cancel"} {
		action := action
		p := map[string]any{"trade_offer_id": id()}
		required := []string{"trade_offer_id"}
		if action == "accept" {
			p["partner"] = steamID
			required = append(required, "partner")
		}
		ops = append(ops, authOp("trade."+action, "write", p, required, action+" one trade offer; pending confirmations are never auto-approved.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			oid := a["trade_offer_id"].(string)
			p := authParams("sessionid", s.sessionID)
			if action == "accept" {
				partner, e := authSteamID(a["partner"])
				if e != nil {
					return nil, e
				}
				p.Set("tradeofferid", oid)
				p.Set("serverid", "1")
				p.Set("partner", partner)
				p.Set("captcha", "")
			}
			r, e := authRequest(ctx, c, "POST", authCommunity+"/tradeoffer/"+oid+"/"+action, p, authCommunity+"/tradeoffer/"+oid, authRequestOptions{})
			if e != nil {
				return nil, e
			}
			if action != "accept" {
				rid, e := authUpID(r["tradeofferid"])
				if e != nil || rid != oid {
					return nil, authMalformed()
				}
			} else {
				pending, e := authPending(r)
				if e != nil {
					return nil, e
				}
				if !pending && r["tradeid"] == nil && r["tradeofferid"] == nil {
					return nil, authMalformed()
				}
			}
			if v, ok := r["tradeid"]; ok {
				if _, e = authUpID(v); e != nil {
					return nil, e
				}
			}
			return authResult(r)
		}))
	}
	ops = append(ops, authOp("confirmations.get_all", "read", map[string]any{}, nil, "Read standing confirmations with no nonce returned; unknown types fail closed.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
		all, e := authConfirmations(ctx, c, s)
		if e != nil {
			return nil, e
		}
		for _, m := range all {
			delete(m, "nonce")
		}
		return all, nil
	}))
	for _, mode := range []string{"accept", "deny", "multiple", "accept_all", "deny_all"} {
		mode := mode
		scope := "admin"
		name := mode
		p := map[string]any{}
		var required []string
		if mode == "accept" || mode == "deny" {
			scope = "write"
			p["confirmation_id"] = id()
			required = []string{"confirmation_id"}
		} else if mode == "multiple" {
			name = "send_multiple"
			p["confirmation_ids"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 200, "uniqueItems": true, "items": id()}
			p["accept"] = boolean
			required = []string{"confirmation_ids", "accept"}
		}
		ops = append(ops, authOp("confirmations."+name, scope, p, required, "Refetch actual server types and nonces; entire selected batch must be types 2,3,12,13.", func(ctx context.Context, c *Context, a map[string]any, s authSession) (any, error) {
			return authConfirmWrite(ctx, c, a, s, mode)
		}))
	}
	return ops
}
