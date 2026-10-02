package steam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type authenticatedFakeTransport func(*http.Request) (*http.Response, error)

func (f authenticatedFakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type authenticatedCall struct {
	method, path, referer, cookie string
	params                        url.Values
}
type authenticatedReply struct {
	status  int
	body    string
	headers http.Header
}

func authenticatedJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func authenticatedState() State {
	return State{"session": map[string]any{"steam_id": "76561198000000001", "access_token": "synthetic-token", "session_id": "synthetic-session", "cookies": []any{map[string]any{"name": "sessionid", "value": "synthetic-session", "domain": "steamcommunity.com", "path": "/", "hostOnly": true, "secure": true, "expires": nil}, map[string]any{"name": "steamLoginSecure", "value": "synthetic-auth", "domain": "steamcommunity.com", "path": "/", "hostOnly": true, "secure": true, "expires": nil}}}, "wallet": map[string]any{"currency": float64(23)}, "guard": map[string]any{"identity_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "device_id": "android:12345678-1234-1234-1234-123456789abc"}}
}
func authenticatedSetup(t *testing.T, replies ...authenticatedReply) (*Context, *[]authenticatedCall) {
	t.Helper()
	calls := []authenticatedCall{}
	tr := NewTransportWithClient(&http.Client{Transport: authenticatedFakeTransport(func(r *http.Request) (*http.Response, error) {
		p := r.URL.Query()
		if r.Method == "POST" {
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				if e := r.ParseMultipartForm(4096); e != nil {
					t.Fatal(e)
				}
				p = r.PostForm
			} else {
				b, e := io.ReadAll(r.Body)
				if e != nil {
					t.Fatal(e)
				}
				p, e = url.ParseQuery(string(b))
				if e != nil {
					t.Fatal(e)
				}
			}
		}
		calls = append(calls, authenticatedCall{r.Method, r.URL.Path, r.Header.Get("Referer"), r.Header.Get("Cookie"), p})
		if len(calls) > len(replies) {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		reply := replies[len(calls)-1]
		status := reply.status
		if status == 0 {
			status = 200
		}
		h := reply.headers
		if h == nil {
			h = http.Header{}
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(reply.body)), Request: r}, nil
	})})
	return &Context{State: authenticatedState(), Transport: tr, Scope: "admin"}, &calls
}
func authenticatedRun(t *testing.T, c *Context, name string, args map[string]any) (any, error) {
	t.Helper()
	for _, op := range AuthenticatedOperations() {
		if op.Name == name {
			return op.Run(context.Background(), c, args)
		}
	}
	t.Fatalf("operation missing: %s", name)
	return nil, nil
}
func authenticatedExpectError(t *testing.T, e error, code string) {
	t.Helper()
	var a *APIError
	if !errors.As(e, &a) || a.Code != code {
		t.Fatalf("expected %s got %v", code, e)
	}
}
func authenticatedAssertParams(t *testing.T, got, want url.Values) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("params got %#v want %#v", got, want)
	}
}
func authenticatedSellArgs() map[string]any {
	return map[string]any{"app": float64(730), "context_id": "2", "asset_id": "99", "to_receive": float64(100), "currency": float64(23)}
}
func authenticatedBuyArgs() map[string]any {
	return map[string]any{"app": float64(730), "market_hash_name": "Synthetic Item", "price": float64(100), "quantity": float64(3), "currency": float64(23)}
}
func authenticatedWallet() map[string]any {
	w := map[string]any{"success": 1, "wallet_currency": 23, "wallet_country": "CN", "wallet_state": "", "wallet_fee_percent": "0.05", "wallet_publisher_fee_percent_default": "0.1"}
	for _, k := range []string{"wallet_fee", "wallet_fee_minimum", "wallet_market_minimum", "wallet_currency_increment", "wallet_fee_base", "wallet_balance", "wallet_delayed_balance", "wallet_max_balance", "wallet_trade_max_balance"} {
		w[k] = "100"
	}
	return w
}

func TestAuthenticatedCatalogAndAbsentAuth(t *testing.T) {
	ops := AuthenticatedOperations()
	if len(ops) != 21 {
		t.Fatalf("got %d operations", len(ops))
	}
	seen := map[string]bool{}
	for _, op := range ops {
		if seen[op.Name] {
			t.Fatalf("duplicate %s", op.Name)
		}
		seen[op.Name] = true
		c, calls := authenticatedSetup(t)
		c.State = State{}
		_, e := op.Run(context.Background(), c, map[string]any{})
		authenticatedExpectError(t, e, "authentication_required")
		if len(*calls) != 0 {
			t.Fatal("request without auth")
		}
		if op.Mutating != (op.Scope != "read") {
			t.Fatal("scope mutation mismatch")
		}
		if op.Schema["additionalProperties"] != false {
			t.Fatal("open schema")
		}
	}
}
func TestAuthenticatedBadPersistedCookieFailsClosed(t *testing.T) {
	c, calls := authenticatedSetup(t)
	s, _ := authObject(c.State["session"])
	cookies, _ := authSlice(s["cookies"])
	cookies = append(cookies, map[string]any{"name": "broken"})
	s["cookies"] = cookies
	_, e := authenticatedRun(t, c, "wallet.info", nil)
	authenticatedExpectError(t, e, "authentication_required")
	if len(*calls) != 0 {
		t.Fatal("network on malformed persisted state")
	}
}
func TestAuthenticatedInventoryExactAndPaging(t *testing.T) {
	for _, reply := range []string{`{"success":1,"total_inventory_count":0,"assets":[],"descriptions":[],"last_assetid":"124","more_items":1}`, `{"success":1,"total_inventory_count":0,"last_assetid":"123","more_items":1}`, `{"success":1,"total_inventory_count":0,"more_items":1}`, `{"success":1,"total_inventory_count":1,"assets":[{"assetid":"1","contextid":"2","classid":"3","amount":"0"}],"descriptions":[]}`} {
		c, calls := authenticatedSetup(t, authenticatedReply{body: reply})
		_, e := authenticatedRun(t, c, "inventory.get", map[string]any{"app": float64(730), "context_id": "2", "start_asset_id": "123", "count": float64(75)})
		if strings.Contains(reply, `"124"`) {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			authenticatedExpectError(t, e, "malformed_upstream_response")
		}
		call := (*calls)[0]
		if call.path != "/inventory/76561198000000001/730/2" || !strings.Contains(call.cookie, "steamLoginSecure=synthetic-auth") {
			t.Fatalf("bad inventory path/cookie: %#v", call)
		}
		authenticatedAssertParams(t, call.params, authParams("l", "english", "count", 75, "raw_asset_properties", 1, "preserve_bbcode", 1, "start_assetid", "123"))
	}
}
func TestAuthenticatedMoneyGuards(t *testing.T) {
	tests := []struct {
		name   string
		args   map[string]any
		wallet any
		code   string
	}{{"market.place_sell_listing", authenticatedSellArgs(), nil, "wallet_currency_required"}, {"market.place_sell_listing", authenticatedSellArgs(), map[string]any{"currency": 1}, "wallet_currency_mismatch"}, {"market.place_buy_order", map[string]any{"app": 730, "market_hash_name": "Item", "price": authMaxInt, "quantity": 2, "currency": 23}, map[string]any{"currency": 23}, "invalid_arguments"}, {"market.buy_listing", map[string]any{"listing_id": "1", "app": 730, "market_hash_name": "Item", "subtotal": authMaxInt, "fee": 1, "currency": 23}, map[string]any{"currency": 23}, "invalid_arguments"}}
	for _, tc := range tests {
		c, calls := authenticatedSetup(t)
		c.State["wallet"] = tc.wallet
		_, e := authenticatedRun(t, c, tc.name, tc.args)
		authenticatedExpectError(t, e, tc.code)
		if len(*calls) != 0 {
			t.Fatal("effect despite rejected money")
		}
	}
	for _, bad := range []any{1.5, -1, mathNaNForAuth(), "100", float64(9007199254740992)} {
		c, calls := authenticatedSetup(t)
		a := authenticatedSellArgs()
		a["to_receive"] = bad
		_, e := authenticatedRun(t, c, "market.place_sell_listing", a)
		authenticatedExpectError(t, e, "invalid_arguments")
		if len(*calls) != 0 {
			t.Fatal("effect despite invalid money")
		}
	}
}
func mathNaNForAuth() float64 { var f float64; return f / f }
func TestAuthenticatedWalletRefresh(t *testing.T) {
	w := authenticatedWallet()
	c, calls := authenticatedSetup(t, authenticatedReply{body: "<script>g_rgWalletInfo = " + authenticatedJSON(w) + ";</script>"}, authenticatedReply{body: `{"success":true}`})
	delete(c.State, "wallet")
	_, e := authenticatedRun(t, c, "market.place_sell_listing", authenticatedSellArgs())
	authenticatedExpectError(t, e, "wallet_currency_required")
	if len(*calls) != 0 {
		t.Fatal("network before trusted wallet")
	}
	v, e := authenticatedRun(t, c, "wallet.info", nil)
	if e != nil {
		t.Fatal(e)
	}
	got, _ := authObject(v)
	if got["currency"] != int64(23) {
		t.Fatalf("currency %#v", got["currency"])
	}
	_, e = authenticatedRun(t, c, "market.place_sell_listing", authenticatedSellArgs())
	if e != nil {
		t.Fatal(e)
	}
	if len(*calls) != 2 {
		t.Fatal("wrong request count")
	}
	c, calls = authenticatedSetup(t, authenticatedReply{body: `<script>not a wallet</script>`})
	_, e = authenticatedRun(t, c, "wallet.info", nil)
	authenticatedExpectError(t, e, "malformed_upstream_response")
	if _, ok := c.State["wallet"]; ok {
		t.Fatal("stale wallet survived failed refresh")
	}
	if len(*calls) != 1 {
		t.Fatal("retry")
	}
}
func TestAuthenticatedFinancialExactFormsNoApproval(t *testing.T) {
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"success":true,"needs_mobile_confirmation":true}`}, authenticatedReply{status: 406, body: `{"need_confirmation":true,"confirmation":{"confirmation_id":"321"}}`}, authenticatedReply{body: `{"wallet_info":{"success":1}}`})
	v, e := authenticatedRun(t, c, "market.place_sell_listing", authenticatedSellArgs())
	if e != nil {
		t.Fatal(e)
	}
	if v.(map[string]any)["pending_confirmation"] != true {
		t.Fatal("pending lost")
	}
	authenticatedAssertParams(t, (*calls)[0].params, authParams("sessionid", "synthetic-session", "appid", 730, "contextid", "2", "assetid", "99", "amount", 1, "price", 100))
	if (*calls)[0].path != "/market/sellitem/" {
		t.Fatal("wrong sell endpoint")
	}
	v, e = authenticatedRun(t, c, "market.place_buy_order", authenticatedBuyArgs())
	if e != nil {
		t.Fatal(e)
	}
	if v.(map[string]any)["pending_confirmation"] != true {
		t.Fatal("pending lost")
	}
	authenticatedAssertParams(t, (*calls)[1].params, authParams("sessionid", "synthetic-session", "currency", 23, "appid", 730, "market_hash_name", "Synthetic Item", "price_total", 300, "quantity", 3, "confirmation", 0))
	_, e = authenticatedRun(t, c, "market.buy_listing", map[string]any{"listing_id": "1", "app": 730, "market_hash_name": "A/B", "subtotal": 100, "fee": 15, "currency": 23})
	if e != nil {
		t.Fatal(e)
	}
	authenticatedAssertParams(t, (*calls)[2].params, authParams("sessionid", "synthetic-session", "currency", 23, "subtotal", 100, "fee", 15, "total", 115, "quantity", 1, "confirmation", 0))
	if (*calls)[2].referer != "https://steamcommunity.com/market/listings/730/A%2FB" {
		t.Fatal("referer escaping")
	}
	if len(*calls) != 3 {
		t.Fatal("auto approval/retry")
	}
}
func TestAuthenticatedCancellationMetadataAndErrors(t *testing.T) {
	for _, name := range []string{"market.cancel_sell_listing", "market.cancel_buy_order"} {
		args := map[string]any{"listing_id": "1"}
		if name == "market.cancel_buy_order" {
			args = map[string]any{"buy_order_id": "1"}
		}
		for _, body := range []string{"", `<html>login</html>`, `{}`} {
			c, calls := authenticatedSetup(t, authenticatedReply{body: body})
			v, e := authenticatedRun(t, c, name, args)
			if body == "" {
				if e != nil {
					t.Fatal(e)
				}
				m := v.(map[string]any)
				if m["upstream_status"] != 200 {
					t.Fatal("missing status")
				}
				if _, ok := m["success"]; ok {
					t.Fatal("invented success")
				}
			} else if e == nil {
				t.Fatal("accepted invalid body")
			}
			if len(*calls) != 1 {
				t.Fatal("retry")
			}
		}
	}
	for _, status := range []int{429, 401, 403, 500} {
		c, calls := authenticatedSetup(t, authenticatedReply{status: status, body: `{}`})
		_, e := authenticatedRun(t, c, "market.cancel_buy_order", map[string]any{"buy_order_id": "1"})
		code := "upstream_http_error"
		if status == 429 {
			code = "upstream_rate_limited"
		}
		if status == 401 || status == 403 {
			code = "authentication_required"
		}
		authenticatedExpectError(t, e, code)
		if len(*calls) != 1 {
			t.Fatal("retry")
		}
	}
}
func TestAuthenticatedCookiesPersistOnError(t *testing.T) {
	c, _ := authenticatedSetup(t, authenticatedReply{body: `{}`, headers: http.Header{"Set-Cookie": []string{"steamLoginSecure=synthetic-rotated; Path=/; Secure"}}})
	_, e := authenticatedRun(t, c, "inventory.get", map[string]any{"app": 730, "context_id": "2"})
	if e == nil {
		t.Fatal("expected error")
	}
	s, _ := authObject(c.State["session"])
	arr, _ := authSlice(s["cookies"])
	found := false
	for _, v := range arr {
		m, _ := authObject(v)
		if m["name"] == "steamLoginSecure" && m["value"] == "synthetic-rotated" {
			found = true
		}
	}
	if !found {
		t.Fatal("rotated cookie lost")
	}
}
func TestAuthenticatedTradeReadSendAndActions(t *testing.T) {
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"response":{"offer":{"tradeofferid":"1"}}}`}, authenticatedReply{body: `{"response":{"next_cursor":3}}`}, authenticatedReply{body: `{"tradeofferid":"9","needs_mobile_confirmation":true}`}, authenticatedReply{body: `{"tradeid":"20","needs_mobile_confirmation":true}`}, authenticatedReply{body: `{"tradeofferid":"12"}`}, authenticatedReply{body: `{"tradeofferid":"13"}`})
	_, e := authenticatedRun(t, c, "trade.get", map[string]any{"trade_offer_id": "1"})
	if e != nil {
		t.Fatal(e)
	}
	authenticatedAssertParams(t, (*calls)[0].params, authParams("access_token", "synthetic-token", "language", "english", "get_descriptions", 1, "tradeofferid", "1"))
	_, e = authenticatedRun(t, c, "trade.get_multiple", map[string]any{"historical_cutoff": float64(100), "cursor": float64(2), "sent": false})
	if e != nil {
		t.Fatal(e)
	}
	authenticatedAssertParams(t, (*calls)[1].params, authParams("access_token", "synthetic-token", "language", "english", "get_descriptions", 1, "active_only", 1, "historical_only", 0, "get_sent_offers", 0, "get_received_offers", 1, "cursor", 2, "time_historical_cutoff", 100))
	_, e = authenticatedRun(t, c, "trade.send", map[string]any{"partner": "76561198000000002", "to_partner": []any{map[string]any{"appid": float64(730), "contextid": "2", "assetid": "7", "amount": float64(1)}}, "from_partner": []any{}, "token": "abc"})
	if e != nil {
		t.Fatal(e)
	}
	call := (*calls)[2]
	var offer map[string]any
	if e = json.Unmarshal([]byte(call.params.Get("json_tradeoffer")), &offer); e != nil {
		t.Fatal(e)
	}
	me, _ := authObject(offer["me"])
	arr, _ := authSlice(me["assets"])
	asset, _ := authObject(arr[0])
	if asset["amount"] != "1" || asset["assetid"] != "7" || offer["version"] != float64(2) {
		t.Fatal("trade assets representation")
	}
	if call.params.Get("trade_offer_create_params") != `{"trade_offer_access_token":"abc"}` || call.params.Get("partner") != "76561198000000002" || call.params.Get("serverid") != "1" || call.params.Get("captcha") != "" {
		t.Fatal("trade form")
	}
	if call.referer != "https://steamcommunity.com/tradeoffer/new/?partner=39734274&token=abc" {
		t.Fatalf("referer %s", call.referer)
	}
	for _, action := range []string{"accept", "decline", "cancel"} {
		args := map[string]any{"trade_offer_id": map[string]string{"accept": "11", "decline": "12", "cancel": "13"}[action]}
		if action == "accept" {
			args["partner"] = "76561198000000002"
		}
		if _, e = authenticatedRun(t, c, "trade."+action, args); e != nil {
			t.Fatal(e)
		}
	}
	authenticatedAssertParams(t, (*calls)[3].params, authParams("sessionid", "synthetic-session", "tradeofferid", "11", "serverid", 1, "partner", "76561198000000002", "captcha", ""))
	for i := 4; i < 6; i++ {
		authenticatedAssertParams(t, (*calls)[i].params, authParams("sessionid", "synthetic-session"))
	}
	if len(*calls) != 6 {
		t.Fatal("retry or approval")
	}
}
func TestAuthenticatedInvalidIDsAssetsAndScopes(t *testing.T) {
	for _, v := range []any{"0", "01", "18446744073709551616", "1/accept", float64(1)} {
		c, calls := authenticatedSetup(t)
		_, e := authenticatedRun(t, c, "trade.get", map[string]any{"trade_offer_id": v})
		authenticatedExpectError(t, e, "invalid_arguments")
		if len(*calls) != 0 {
			t.Fatal("network on bad ID")
		}
	}
	for _, scope := range []string{"read", "write", "unexpected", "bulkadmin"} {
		c, calls := authenticatedSetup(t)
		c.Scope = scope
		_, e := authenticatedRun(t, c, "confirmations.accept_all", nil)
		authenticatedExpectError(t, e, "insufficient_scope")
		if len(*calls) != 0 {
			t.Fatal("network without admin")
		}
	}
	for _, assets := range []any{[]any{map[string]any{"appid": 730, "contextid": "2", "assetid": "1", "amount": 0}}, []any{map[string]any{"appid": 730, "contextid": "2", "assetid": "1", "amount": 1}, map[string]any{"appid": 730, "contextid": "2", "assetid": "1", "amount": 2}}} {
		c, calls := authenticatedSetup(t)
		_, e := authenticatedRun(t, c, "trade.send", map[string]any{"partner": "76561198000000002", "to_partner": assets, "from_partner": []any{}})
		authenticatedExpectError(t, e, "invalid_arguments")
		if len(*calls) != 0 {
			t.Fatal("network on bad assets")
		}
	}
}
func TestAuthenticatedConfirmationTypesFailClosedEntireBatch(t *testing.T) {
	for _, typ := range []int{0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 99} {
		for _, mode := range []string{"accept", "deny", "send_multiple", "accept_all", "deny_all"} {
			c, calls := authenticatedSetup(t, authenticatedReply{body: authenticatedJSON(map[string]any{"success": 1, "conf": []any{map[string]any{"id": "1", "nonce": "21", "type": 2}, map[string]any{"id": "2", "nonce": "22", "type": typ}}})})
			a := map[string]any{}
			if mode == "accept" || mode == "deny" {
				a["confirmation_id"] = "2"
			}
			if mode == "send_multiple" {
				a["confirmation_ids"] = []any{"1", "2"}
				a["accept"] = true
			}
			_, e := authenticatedRun(t, c, "confirmations."+mode, a)
			code := "confirmation_type_denied"
			if typ == 99 {
				code = "unknown_confirmation_type"
			}
			authenticatedExpectError(t, e, code)
			if len(*calls) != 1 || (*calls)[0].path != "/mobileconf/getlist" {
				t.Fatal("unsafe batch mutated")
			}
		}
	}
}
func TestAuthenticatedConfirmationNonceRedactionAndExactWrites(t *testing.T) {
	for _, typ := range []int{2, 3, 12, 13} {
		for _, mode := range []string{"accept", "deny"} {
			list := authenticatedJSON(map[string]any{"success": 1, "conf": []any{map[string]any{"id": "1", "nonce": "22", "type": typ}}})
			c, calls := authenticatedSetup(t, authenticatedReply{body: list}, authenticatedReply{body: `{"success":1}`})
			c.Scope = "write"
			_, e := authenticatedRun(t, c, "confirmations."+mode, map[string]any{"confirmation_id": "1"})
			if e != nil {
				t.Fatal(e)
			}
			call := (*calls)[1]
			tag := "cancel"
			if mode == "accept" {
				tag = "allow"
			}
			if call.method != "GET" || call.path != "/mobileconf/ajaxop" || call.params.Get("ck") != "22" || call.params.Get("cid") != "1" || call.params.Get("op") != tag || call.params.Get("tag") != tag || call.params.Get("k") == "" {
				t.Fatalf("bad confirmation request %#v", call)
			}
			if len(*calls) != 2 {
				t.Fatal("retry")
			}
		}
	}
	c, _ := authenticatedSetup(t, authenticatedReply{body: `{"success":1,"conf":[{"id":"1","nonce":"22","type":2}]}`})
	v, e := authenticatedRun(t, c, "confirmations.get_all", nil)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(authenticatedJSON(v), "nonce") {
		t.Fatal("nonce exposed")
	}
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"success":1,"conf":[{"id":"1","nonce":"21","type":3},{"id":"2","nonce":"22","type":12}]}`}, authenticatedReply{body: `{"success":1}`})
	v, e = authenticatedRun(t, c, "confirmations.send_multiple", map[string]any{"confirmation_ids": []any{"2", "1"}, "accept": false})
	if e != nil {
		t.Fatal(e)
	}
	call := (*calls)[1]
	if call.method != "POST" || call.path != "/mobileconf/multiajaxop" || call.params.Get("op") != "cancel" || !reflect.DeepEqual(call.params["cid[]"], []string{"2", "1"}) || !reflect.DeepEqual(call.params["ck[]"], []string{"22", "21"}) {
		t.Fatalf("bad bulk form %#v", call)
	}
	if strings.Contains(authenticatedJSON(v), "nonce") {
		t.Fatal("nonce exposed")
	}
}
func TestAuthenticatedLargeJSONNumbersUseDecimalForms(t *testing.T) {
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"success":1}`}, authenticatedReply{body: `{"response":{"next_cursor":0}}`})
	a := authenticatedSellArgs()
	a["app"] = float64(4294967295)
	a["to_receive"] = float64(authMaxInt)
	if _, e := authenticatedRun(t, c, "market.place_sell_listing", a); e != nil {
		t.Fatal(e)
	}
	if (*calls)[0].params.Get("appid") != "4294967295" || (*calls)[0].params.Get("price") != "9007199254740991" {
		t.Fatal("exponent notation leaked into money/app form")
	}
	if _, e := authenticatedRun(t, c, "trade.get_multiple", map[string]any{"cursor": float64(authMaxInt), "historical_cutoff": float64(authMaxInt)}); e != nil {
		t.Fatal(e)
	}
	if (*calls)[1].params.Get("cursor") != "9007199254740991" || (*calls)[1].params.Get("time_historical_cutoff") != "9007199254740991" {
		t.Fatal("exponent notation leaked into paging form")
	}
}
func TestAuthenticatedConfirmationMissingDuplicateAndEmpty(t *testing.T) {
	for _, body := range []string{`{"success":1,"conf":[{"id":"1","nonce":"0","type":2}]}`, `{"success":1,"conf":[{"id":"1","nonce":"2","type":2},{"id":"1","nonce":"3","type":3}]}`} {
		c, calls := authenticatedSetup(t, authenticatedReply{body: body})
		_, e := authenticatedRun(t, c, "confirmations.accept_all", nil)
		authenticatedExpectError(t, e, "malformed_upstream_response")
		if len(*calls) != 1 {
			t.Fatal("malformed list mutated")
		}
	}
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"success":1,"conf":[]}`})
	_, e := authenticatedRun(t, c, "confirmations.accept", map[string]any{"confirmation_id": "1"})
	authenticatedExpectError(t, e, "confirmation_not_found")
	if len(*calls) != 1 {
		t.Fatal("missing confirmation mutated")
	}
	c, calls = authenticatedSetup(t, authenticatedReply{body: `{"success":1,"conf":[]}`})
	v, e := authenticatedRun(t, c, "confirmations.deny_all", nil)
	if e != nil {
		t.Fatal(e)
	}
	if authenticatedJSON(v) != `{"processed_ids":[],"success":true}` || len(*calls) != 1 {
		t.Fatal("empty batch mutated or incorrect output")
	}
	c, calls = authenticatedSetup(t)
	_, e = authenticatedRun(t, c, "confirmations.send_multiple", map[string]any{"confirmation_ids": []any{"1", "1"}, "accept": true})
	authenticatedExpectError(t, e, "invalid_arguments")
	if len(*calls) != 0 {
		t.Fatal("duplicate IDs reached network")
	}
}
func TestAuthenticatedExplicitNullFlagsFailClosed(t *testing.T) {
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"success":1,"needs_mobile_confirmation":null}`})
	_, e := authenticatedRun(t, c, "market.place_sell_listing", authenticatedSellArgs())
	authenticatedExpectError(t, e, "malformed_upstream_response")
	if len(*calls) != 1 {
		t.Fatal("retry")
	}
}

func TestAuthenticatedRemainingMarketReads(t *testing.T) {
	c, calls := authenticatedSetup(t, authenticatedReply{body: `{"success":1,"listings":[],"listings_to_confirm":[],"buy_orders":[],"num_active_listings":0}`}, authenticatedReply{body: `{"success":1,"active":1,"purchased":0,"quantity":2,"quantity_remaining":2}`})
	_, e := authenticatedRun(t, c, "market.get_user_listings", map[string]any{"start": 10, "count": 25})
	if e != nil {
		t.Fatal(e)
	}
	authenticatedAssertParams(t, (*calls)[0].params, authParams("norender", 1, "start", 10, "count", 25))
	_, e = authenticatedRun(t, c, "market.get_buy_order_status", map[string]any{"buy_order_id": "3"})
	if e != nil {
		t.Fatal(e)
	}
	authenticatedAssertParams(t, (*calls)[1].params, authParams("sessionid", "synthetic-session", "buy_orderid", "3"))
}
