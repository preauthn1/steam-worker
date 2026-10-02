package steam

import (
	"log"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var qrURLPattern = regexp.MustCompile(`^https://s\.team/q/(0|[1-9][0-9]{0,4})/(0|[1-9][0-9]{0,19})$`)

func qrChallenge(raw string) (uint16, string, error) {
	m := qrURLPattern.FindStringSubmatch(raw)
	if m == nil {
		return 0, "", fail(400, "invalid_arguments")
	}
	v, e := strconv.ParseUint(m[1], 10, 16)
	if e != nil {
		return 0, "", fail(400, "invalid_arguments")
	}
	if _, e = strconv.ParseUint(m[2], 10, 64); e != nil {
		return 0, "", fail(400, "invalid_arguments")
	}
	return uint16(v), m[2], nil
}

type mobileCredentials struct {
	steam, access, secret string
	key                   []byte
}

func qrMobile(c *Context) (mobileCredentials, error) {
	var out mobileCredentials
	s := object(c.State["session"])
	if s["platform"] != "mobile" {
		return out, fail(409, "mobile_session_required")
	}
	out.steam = textValue(s["steam_id"])
	if !positiveID.MatchString(out.steam) {
		return out, fail(409, "mobile_session_required")
	}
	if _, e := strconv.ParseUint(out.steam, 10, 64); e != nil {
		return out, fail(409, "mobile_session_required")
	}
	out.access = textValue(s["access_token"])
	if out.access == "" || len(out.access) > 16384 {
		return out, fail(409, "mobile_session_required")
	}
	exp, ok := s["access_expires_at"].(float64)
	if !ok || math.IsNaN(exp) || math.IsInf(exp, 0) || exp <= timestamp() {
		return out, fail(409, "session_expired")
	}
	parts := strings.Split(out.access, ".")
	meta, e := jwtClaims(out.access)
	if e != nil || len(parts) != 3 || parts[0] == "" || parts[2] == "" || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(parts[1]) || meta.Sub != out.steam || !contains(meta.Aud, "mobile") || contains(meta.Aud, "derive") {
		return out, fail(409, "invalid_mobile_access_token")
	}
	out.secret = textValue(object(c.State["guard"])["shared_secret"])
	out.key, e = base64.StdEncoding.DecodeString(out.secret)
	if e != nil || len(out.key) != 20 || base64.StdEncoding.EncodeToString(out.key) != out.secret {
		return out, fail(409, "shared_secret_required")
	}
	return out, nil
}
func qrBinding(s mobileCredentials) string {
	b, _ := json.Marshal([]string{s.steam, s.access, s.secret})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func qrSign(key []byte, version uint16, client, steam string) []byte {
	b := make([]byte, 18)
	binary.LittleEndian.PutUint16(b, version)
	c, _ := strconv.ParseUint(client, 10, 64)
	s, _ := strconv.ParseUint(steam, 10, 64)
	binary.LittleEndian.PutUint64(b[2:], c)
	binary.LittleEndian.PutUint64(b[10:], s)
	h := hmac.New(sha256.New, key)
	h.Write(b)
	return h.Sum(nil)
}
func qrMetadata(body []byte, version uint16) (map[string]any, error) {
	m, e := DecodeProto(body)
	if e != nil {
		return nil, invalidResponse()
	}
	out := map[string]any{}
	names := []string{"ip", "geoloc", "city", "state", "country", "platform_type", "device_friendly_name", "version", "login_history", "requestor_location_mismatch", "high_usage_login", "requested_persistence", "device_trust", "app_type"}
	for i, name := range names {
		n := i + 1
		wire := 0
		if n <= 5 || n == 7 {
			wire = 2
		}
		fields := m[n]
		if len(fields) > 1 || (len(fields) == 1 && fields[0].Wire != wire) {
			return nil, invalidResponse()
		}
		if wire == 2 {
			b := protoBytes(m, n)
			if len(b) > 2048 || !utf8.Valid(b) {
				return nil, invalidResponse()
			}
			out[name] = strings.TrimPrefix(string(b), "\ufeff")
		} else {
			v := protoInt(m, n)
			if v > 0x7fffffff {
				return nil, invalidResponse()
			}
			if n == 10 || n == 11 {
				if v > 1 {
					return nil, invalidResponse()
				}
				out[name] = v == 1
			} else {
				out[name] = float64(v)
			}
		}
	}
	if len(m[8]) == 0 || protoInt(m, 8) != uint64(version) || protoInt(m, 12) > 1 {
		return nil, invalidResponse()
	}
	return out, nil
}
func qrInspect(ctx context.Context, c *Context, args map[string]any) (any, error) {
	version, client, e := qrChallenge(textValue(args["qr_url"]))
	if e != nil {
		return nil, e
	}
	s, e := qrMobile(c)
	if e != nil {
		return nil, e
	}
	delete(c.State, "qr_review")
	binding := qrBinding(s)
	b, e := CallService(ctx, c.Transport, "IAuthenticationService", "GetAuthSessionInfo", new(ProtoWriter).Uint(1, decimal(client)).Finish(), s.access, "")
	if e != nil {
		return nil, e
	}
	meta, e := qrMetadata(b, version)
	if e != nil {
		return nil, e
	}
	current, e := qrMobile(c)
	if e != nil {
		return nil, e
	}
	if qrBinding(current) != binding {
		return nil, fail(409, "qr_review_session_changed")
	}
	now := timestamp()
	handle := randomHandle()
	c.State["qr_review"] = map[string]any{"review_handle": handle, "steam_id": s.steam, "credential_binding": binding, "client_id": client, "version": float64(version), "inspected_at": now, "expires_at": now + 120, "metadata": meta}
	out := map[string]any{"status": "review_required", "review_handle": handle, "expires_at": now + 120, "requires_confirmation": true}
	for k, v := range meta {
		out[k] = v
	}
	return out, nil
}
func qrSubmit(ctx context.Context, c *Context, args map[string]any, confirm bool) (any, error) {
	s, e := qrMobile(c)
	if e != nil {
		return nil, e
	}
	r := object(c.State["qr_review"])
	if textValue(r["review_handle"]) == "" || r["review_handle"] != args["review_handle"] {
		return nil, fail(409, "qr_review_handle_mismatch")
	}
	inspected, ok1 := r["inspected_at"].(float64)
	expires, ok2 := r["expires_at"].(float64)
	if !ok1 || !ok2 || math.IsNaN(inspected) || math.IsNaN(expires) || math.IsInf(inspected, 0) || math.IsInf(expires, 0) || inspected > timestamp() || expires <= timestamp() || expires > inspected+120 {
		delete(c.State, "qr_review")
		return nil, fail(409, "qr_review_expired")
	}
	if r["steam_id"] != s.steam || r["credential_binding"] != qrBinding(s) {
		delete(c.State, "qr_review")
		return nil, fail(409, "qr_review_session_changed")
	}
	delete(c.State, "qr_review")
	version, ok := r["version"].(float64)
	if !ok || math.Trunc(version) != version || textValue(r["client_id"]) == "" {
		return nil, invalidResponse()
	}
	v, client, e := qrChallenge("https://s.team/q/" + strconv.FormatFloat(version, 'f', 0, 64) + "/" + textValue(r["client_id"]))
	if e != nil {
		return nil, e
	}
	meta := object(r["metadata"])
	if meta == nil || (number(meta["requested_persistence"]) != 0 && number(meta["requested_persistence"]) != 1) || meta["requested_persistence"] == nil {
		return nil, invalidResponse()
	}
	signature := qrSign(s.key, v, client, s.steam)
	if expires <= timestamp() {
		return nil, fail(409, "qr_review_expired")
	}
	current, e := qrMobile(c)
	if e != nil {
		return nil, e
	}
	if qrBinding(current) != r["credential_binding"] {
		return nil, fail(409, "qr_review_session_changed")
	}
	_, e = CallService(ctx, c.Transport, "IAuthenticationService", "UpdateAuthSessionWithMobileConfirmation", new(ProtoWriter).Uint(1, uint64(v)).Uint(2, decimal(client)).Fixed64(3, decimal(s.steam)).Bytes(4, signature).Bool(5, confirm).Uint(6, uint64(number(meta["requested_persistence"]))).Finish(), s.access, "")
	if e != nil {
		log.Printf("qr_approve upstream error confirm=%v: %v", confirm, e)
		return nil, e
	}
	status := "denied"
	if confirm {
		status = "approved"
	}
	return map[string]any{"status": status}, nil
}
func QRApprovalOperations() []Operation {
	spec := func(name string, mutating bool, props map[string]any, run func(context.Context, *Context, map[string]any) (any, error)) Operation {
		required := []string{}
		for k := range props {
			required = append(required, k)
		}
		op := Operation{Name: name, Scope: "admin", Mutating: mutating, Description: "Inspect or submit one mobile QR decision; uncertain submissions are never retried.", Schema: schema(props, required)}
		op.Run = func(ctx context.Context, c *Context, args map[string]any) (any, error) {
			if c.Scope != "admin" {
				return nil, fail(403, "scope_denied")
			}
			if e := ValidateArgs(op, args); e != nil {
				return nil, e
			}
			return run(ctx, c, args)
		}
		return op
	}
	handle := map[string]any{"review_handle": map[string]any{"type": "string", "pattern": "^[0-9a-f]{48}$"}}
	return []Operation{spec("session.qr_inspect", false, map[string]any{"qr_url": map[string]any{"type": "string", "minLength": 1, "maxLength": 64}}, qrInspect), spec("session.qr_approve", true, handle, func(ctx context.Context, c *Context, args map[string]any) (any, error) {
		return qrSubmit(ctx, c, args, true)
	}), spec("session.qr_deny", true, handle, func(ctx context.Context, c *Context, args map[string]any) (any, error) {
		return qrSubmit(ctx, c, args, false)
	}), spec("session.qr_code_approve", true, handle, qrCodeApprove)}
}

// qrCodeApprove approves a previously inspected QR login using the
// UpdateAuthSessionWithSteamGuardCode path (device TOTP) instead of the
// mobile-confirmation HMAC. Works for accounts whose authenticator exists
// (even pre-finalize) as long as Steam accepts its TOTP: the code is derived
// locally from the stored shared_secret and never returned to the caller.
func qrCodeApprove(ctx context.Context, c *Context, args map[string]any) (any, error) {
	s, e := qrMobile(c)
	if e != nil {
		return nil, e
	}
	r := object(c.State["qr_review"])
	if textValue(r["review_handle"]) == "" || r["review_handle"] != args["review_handle"] {
		return nil, fail(409, "qr_review_handle_mismatch")
	}
	inspected, ok1 := r["inspected_at"].(float64)
	expires, ok2 := r["expires_at"].(float64)
	if !ok1 || !ok2 || inspected > timestamp() || expires <= timestamp() || expires > inspected+120 {
		delete(c.State, "qr_review")
		return nil, fail(409, "qr_review_expired")
	}
	if r["steam_id"] != s.steam || r["credential_binding"] != qrBinding(s) {
		delete(c.State, "qr_review")
		return nil, fail(409, "qr_review_session_changed")
	}
	delete(c.State, "qr_review")
	version, ok := r["version"].(float64)
	if !ok || math.Trunc(version) != version || textValue(r["client_id"]) == "" {
		return nil, invalidResponse()
	}
	client := textValue(r["client_id"])
	code, e := GenerateAuthCode(s.secret, int64(timestamp()))
	if e != nil {
		return nil, e
	}
	_, e = CallService(ctx, c.Transport, "IAuthenticationService", "UpdateAuthSessionWithSteamGuardCode",
		new(ProtoWriter).Uint(1, decimal(client)).Fixed64(2, decimal(s.steam)).String(3, code).Uint(4, 3).Finish(), "", "")
	if e != nil {
		return nil, e
	}
	return map[string]any{"status": "approved"}, nil
}
