package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pwServer(t *testing.T) http.Handler {
	t.Helper()
	h, e := New(Config{APIKeysJSON: testKeys(), StateKeyHex: strings.Repeat("11", 32), DataDir: t.TempDir(), HTML: []byte("<html>synthetic</html>"), CSP: "default-src 'none'"})
	if e != nil {
		t.Fatal(e)
	}
	return h
}

func do(h http.Handler, method, path, bearer, body string) (int, map[string]any) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func TestConsolePasswordFlow(t *testing.T) {
	h := pwServer(t)
	admin := strings.Repeat("a", 32)

	if st, m := do(h, "GET", "/v1/session/password", "", ""); st != 200 || m["set"] != false {
		t.Fatalf("status before set: %d %v", st, m)
	}
	if st, m := do(h, "POST", "/v1/session/login", "", `{"password":"hunter2hunter2"}`); st != 409 || errCode(m) != "password_not_set" {
		t.Fatalf("login before set: %d %v", st, m)
	}
	// setting requires the admin token
	if st, _ := do(h, "POST", "/v1/session/password", "", `{"password":"my-own-pass"}`); st != 401 {
		t.Fatalf("set without auth: %d", st)
	}
	if st, m := do(h, "POST", "/v1/session/password", admin, `{"password":"short"}`); st != 400 || errCode(m) != "weak_password" {
		t.Fatalf("weak: %d %v", st, m)
	}
	if st, m := do(h, "POST", "/v1/session/password", admin, `{"password":"my-own-pass"}`); st != 200 {
		t.Fatalf("set: %d %v", st, m)
	}
	if st, m := do(h, "GET", "/v1/session/password", "", ""); st != 200 || m["set"] != true {
		t.Fatalf("status after set: %d %v", st, m)
	}
	if st, m := do(h, "POST", "/v1/session/login", "", `{"password":"wrong-pass!"}`); st != 401 || errCode(m) != "wrong_password" {
		t.Fatalf("wrong pw: %d %v", st, m)
	}
	st, m := do(h, "POST", "/v1/session/login", "", `{"password":"my-own-pass"}`)
	tok, _ := m["token"].(string)
	if st != 200 || !strings.HasPrefix(tok, "sess_") || len(tok) < 40 {
		t.Fatalf("login: %d %v", st, m)
	}
	// session token works as admin on account routes and catalog
	if st, _ := do(h, "GET", "/v1/accounts", tok, ""); st != 200 {
		t.Fatalf("session list accounts: %d", st)
	}
	// a session cannot change the password (needs the real admin token)
	if st, _ := do(h, "POST", "/v1/session/password", tok, `{"password":"another-pass"}`); st != 403 {
		t.Fatalf("session changing password: %d", st)
	}
	// logout revokes
	if st, _ := do(h, "POST", "/v1/session/logout", tok, ""); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	if st, _ := do(h, "GET", "/v1/accounts", tok, ""); st != 401 {
		t.Fatalf("after logout: %d", st)
	}
	// password change signs out existing sessions
	_, m = do(h, "POST", "/v1/session/login", "", `{"password":"my-own-pass"}`)
	tok2, _ := m["token"].(string)
	do(h, "POST", "/v1/session/password", admin, `{"password":"brand-new-pass"}`)
	if st, _ := do(h, "GET", "/v1/accounts", tok2, ""); st != 401 {
		t.Fatalf("session survived password change: %d", st)
	}
}

func TestConsolePasswordRateLimitAndExpiry(t *testing.T) {
	a := newConsoleAuth(t.TempDir())
	now := time.Unix(1_800_000_000, 0)
	a.now = func() time.Time { return now }
	if e := a.setPassword("correct-horse"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < maxFailsWindow; i++ {
		if _, _, e := a.login("nope-nope-nope"); errorCode(e) != "wrong_password" {
			t.Fatalf("attempt %d: %v", i, e)
		}
	}
	if _, _, e := a.login("correct-horse"); errorCode(e) != "too_many_attempts" {
		t.Fatalf("expected lockout, got %v", e)
	}
	now = now.Add(failWindow + time.Second)
	tok, _, e := a.login("correct-horse")
	if e != nil || !a.check(tok) {
		t.Fatalf("after window: %v", e)
	}
	now = now.Add(sessionTTL)
	if a.check(tok) {
		t.Fatal("session should expire")
	}
	if a.check("not-a-session") || a.check("sess_forged") {
		t.Fatal("forged token accepted")
	}
}
