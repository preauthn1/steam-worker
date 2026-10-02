package steam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// guardEnrollPhase1 calls ITwoFactorService/AddAuthenticator with an
// authenticated mobile session, stores the pending enrollment in encrypted
// state, and returns only non-secret fields (plus the SMS/email activation
// hint). The shared/identity secrets never leave the encrypted store.
func guardEnrollPhase1(ctx context.Context, c *Context, _ map[string]any) (any, error) {
	s, e := activeSession(c)
	if e != nil {
		return nil, e
	}
	if s["platform"] != "mobile" {
		return nil, fail(409, "mobile_session_required")
	}
	steam := textValue(s["steam_id"])
	id, e := strconv.ParseUint(steam, 10, 64)
	if e != nil {
		return nil, fail(409, "mobile_session_required")
	}
	device := textValue(object(object(c.State["guard"])["enroll"])["device_id"])
	if device == "" {
		device = "android:" + randomUUID()
	}
	b, e := CallService(ctx, c.Transport, "ITwoFactorService", "AddAuthenticator",
		new(ProtoWriter).
			Fixed64(1, id).    // steamid
			Uint(4, 1).        // authenticator_type = phone
			String(5, device). // device_identifier
			Uint(8, 2).        // version
			Finish(), textValue(s["access_token"]), "")
	if e != nil {
		return nil, e
	}
	m, e := DecodeProto(b)
	if e != nil {
		return nil, invalidResponse()
	}
	shared := protoString(m, 1)
	identity := protoString(m, 8)
	if shared == "" || identity == "" {
		// Steam refused: status field 10 carries EResult.
		return nil, fail(409, "upstream_eresult_"+strconv.FormatUint(protoInt(m, 10), 10))
	}
	// Steam returns raw bytes; the stored format (and every consumer:
	// guardMAC, qrMobile, configureGuard) expects base64 text.
	shared = base64.StdEncoding.EncodeToString([]byte(shared))
	identity = base64.StdEncoding.EncodeToString([]byte(identity))
	now := timestamp()
	c.State["guard"] = map[string]any{
		"shared_secret":   shared,
		"identity_secret": identity,
		"device_id":       device,
		"revocation_code": protoString(m, 3),
		"serial_number":   strconv.FormatUint(protoInt(m, 2), 10),
		"token_gid":       protoString(m, 7),
		"enrolled_at":     now,
		"enrollment":      "pending_finalize",
	}
	return map[string]any{
		"status":            "activation_required",
		"phone_hint":        protoString(m, 11),
		"confirm_type":      protoInt(m, 12),
		"device_id":         device,
		"expires_at":        now + 300,
	}, nil
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("random source unavailable")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return strings.ToLower(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

// guardEnrollFinalize validates the code the user received (SMS to the bound
// phone, or email depending on confirm_type), then finalizes enrollment. On
// success the guard is fully configured: future logins can use TOTP generated
// locally from the stored shared_secret, and email confirmation retires.
func guardEnrollFinalize(ctx context.Context, c *Context, args map[string]any) (any, error) {
	g := object(c.State["guard"])
	if textValue(g["enrollment"]) != "pending_finalize" {
		return nil, fail(409, "guard_not_pending_finalize")
	}
	s, e := activeSession(c)
	if e != nil {
		return nil, e
	}
	code := textValue(args["activation_code"])
	// Current TOTP derived locally from the just-enrolled shared_secret.
	totp, e := GenerateAuthCode(textValue(g["shared_secret"]), int64(timestamp()))
	if e != nil {
		return nil, e
	}
	w := new(ProtoWriter).
		Fixed64(1, mustUint64(textValue(s["steam_id"]))).
		String(2, totp).
		Uint(3, uint64(timestamp()))
	if code != "" {
		w = w.String(4, code) // activation_code: SMS code when a phone is bound
	}
	// validate_sms_code omitted (= false): attempt TOTP-only activation.
	b, e := CallService(ctx, c.Transport, "ITwoFactorService", "FinalizeAddAuthenticator", w.Finish(), textValue(s["access_token"]), "")
	if e != nil {
		return nil, e
	}
	m, e := DecodeProto(b)
	if e != nil {
		return nil, invalidResponse()
	}
	if protoInt(m, 1) != 1 { // success flag
		return nil, fail(409, "upstream_eresult_"+strconv.FormatUint(protoInt(m, 4), 10))
	}
	g["enrollment"] = "active"
	c.State["guard"] = g
	return map[string]any{"status": "active", "steamguard_scheme": 2}, nil
}

func mustUint64(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// guardRecoveryCode returns the stored revocation code so the owner can back
// it up. This is the ONLY way to regain the account if the enrolled
// authenticator (and this server's state) is lost, for accounts without a
// bound phone number. Admin scope; write-audited like other sensitive reads.
func guardRecoveryCode(_ context.Context, c *Context, _ map[string]any) (any, error) {
	g := object(c.State["guard"])
	code := textValue(g["revocation_code"])
	if code == "" {
		return nil, fail(409, "guard_not_configured")
	}
	return map[string]any{"revocation_code": code, "advice": "backup_offline"}, nil
}

// guardCurrentCode returns the current 5-char TOTP derived locally from the
// stored shared_secret (valid ~30s). Never contacts Steam.
func guardCurrentCode(_ context.Context, c *Context, _ map[string]any) (any, error) {
	g := object(c.State["guard"])
	secret := textValue(g["shared_secret"])
	if secret == "" {
		return nil, fail(409, "guard_not_configured")
	}
	code, e := GenerateAuthCode(secret, int64(timestamp()))
	if e != nil {
		return nil, e
	}
	remaining := 30 - int64(timestamp())%30
	return map[string]any{"code": code, "expires_in": float64(remaining)}, nil
}
