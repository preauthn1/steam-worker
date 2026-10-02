package steam

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

func publicTime(ctx context.Context, c *Context, args map[string]any) (any, error) {
	w := new(ProtoWriter)
	if v, ok := args["sender_time"]; ok {
		w.Uint(1, uint64(int64(number(v))))
	}
	b, e := CallService(ctx, c.Transport, "ITwoFactorService", "QueryTime", w.Finish(), "", "")
	if e != nil {
		return nil, e
	}
	m, e := DecodeProto(b)
	if e != nil || len(m[1]) == 0 || (m[1][0].Wire != 0 && m[1][0].Wire != 1 && m[1][0].Wire != 5) {
		return nil, invalidResponse()
	}
	return map[string]any{"server_time": strconv.FormatUint(protoInt(m, 1), 10)}, nil
}

var moneyNonNumeric = regexp.MustCompile(`[^0-9,.-]`)

func parseMoney(v any) any {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	s = moneyNonNumeric.ReplaceAllString(s, "")
	s = strings.Replace(s, ",", ".", 1)
	if s == "" {
		return float64(0)
	}
	n, e := strconv.ParseFloat(s, 64)
	if e != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return nil
	}
	return math.Floor(n*100 + 0.5)
}
func publicPrice(ctx context.Context, c *Context, args map[string]any) (any, error) {
	name, ok := args["obj"].(string)
	if !ok || len(utf16.Encode([]rune(name))) > 500 {
		return nil, fail(400, "invalid_arguments")
	}
	app, currency := float64(730), float64(1)
	if v, ok := args["app"]; ok {
		app = number(v)
	}
	if v, ok := args["currency"]; ok {
		currency = number(v)
	}
	params := url.Values{"country": []string{"US"}, "currency": []string{strconv.FormatFloat(currency, 'f', -1, 64)}, "appid": []string{strconv.FormatFloat(app, 'f', -1, 64)}, "market_hash_name": []string{name}}
	h := http.Header{}
	if v, ok := args["if_modified_since"].(string); ok {
		h.Set("If-Modified-Since", v)
	}
	r, e := c.Transport.Request(ctx, "GET", "https://steamcommunity.com/market/priceoverview/?"+params.Encode(), h, nil, "")
	if e != nil {
		return nil, e
	}
	if r.Status == 304 {
		return map[string]any{"not_modified": true}, nil
	}
	if r.Status == 429 {
		return nil, fail(429, "upstream_rate_limited")
	}
	if r.Status >= 400 {
		return nil, fail(502, "upstream_http_"+strconv.Itoa(r.Status))
	}
	var data map[string]any
	if json.Unmarshal(r.Body, &data) != nil || data == nil {
		return nil, invalidResponse()
	}
	if data["success"] != true {
		return nil, fail(502, "upstream_unsuccessful")
	}
	out := map[string]any{"lowest_price_minor": parseMoney(data["lowest_price"]), "median_price_minor": parseMoney(data["median_price"])}
	for _, k := range []string{"lowest_price", "median_price", "volume"} {
		out[k] = nil
		if v, ok := data[k].(string); ok {
			out[k] = v
		}
	}
	return out, nil
}
func PublicOperations() []Operation {
	return []Operation{{Name: "public.server_time", Scope: "read", Description: "Steam server time for Guard code alignment.", Schema: schema(map[string]any{"sender_time": map[string]any{"type": "integer"}}, nil), Run: publicTime}, {Name: "public.market.get_price_overview", Scope: "read", Description: "Public market price overview. Monetary strings are preserved without lossy parsing.", Schema: schema(map[string]any{"obj": map[string]any{"type": "string", "maxLength": 500}, "app": map[string]any{"type": "integer", "minimum": 1}, "currency": map[string]any{"type": "integer", "minimum": 1}, "if_modified_since": map[string]any{"type": "string"}}, []string{"obj"}), Run: publicPrice}}
}
