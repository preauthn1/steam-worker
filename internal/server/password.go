package server

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Console password login: the owner picks a memorable password (set once with
// the admin token). Logging in with it mints a short-lived, in-memory session
// token that acts as the admin principal. Only a PBKDF2-SHA256 hash is stored.

const (
	pwIterations   = 210000
	sessionTTL     = 12 * time.Hour
	sessionPrefix  = "sess_"
	failWindow     = 15 * time.Minute
	maxFailsWindow = 10
)

type pwFile struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
	Iter int    `json:"iter"`
}

type consoleAuth struct {
	mu       sync.Mutex
	path     string
	sessions map[[32]byte]time.Time
	fails    []time.Time
	now      func() time.Time
}

func newConsoleAuth(dataDir string) *consoleAuth {
	return &consoleAuth{path: filepath.Join(dataDir, "console-password.json"), sessions: map[[32]byte]time.Time{}, now: time.Now}
}

func (a *consoleAuth) load() (*pwFile, bool) {
	raw, e := os.ReadFile(a.path)
	if e != nil {
		return nil, false
	}
	var f pwFile
	if json.Unmarshal(raw, &f) != nil || f.Iter < 100000 || f.Salt == "" || f.Hash == "" {
		return nil, false
	}
	return &f, true
}

func (a *consoleAuth) isSet() bool { _, ok := a.load(); return ok }

func validPassword(p string) bool {
	n := utf8.RuneCountInString(p)
	return utf8.ValidString(p) && n >= 8 && n <= 128 && strings.TrimSpace(p) == p
}

func derive(password string, salt []byte, iter int) []byte {
	k, _ := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	return k
}

func (a *consoleAuth) setPassword(password string) error {
	if !validPassword(password) {
		return apiError(400, "weak_password")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	f := pwFile{Salt: base64.RawStdEncoding.EncodeToString(salt), Hash: base64.RawStdEncoding.EncodeToString(derive(password, salt, pwIterations)), Iter: pwIterations}
	raw, _ := json.Marshal(f)
	tmp := a.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil || os.Rename(tmp, a.path) != nil {
		return apiError(500, "internal_error")
	}
	a.mu.Lock()
	a.sessions = map[[32]byte]time.Time{} // changing the password signs everyone out
	a.mu.Unlock()
	return nil
}

func (a *consoleAuth) login(password string) (string, time.Time, error) {
	a.mu.Lock()
	now := a.now()
	kept := a.fails[:0]
	for _, t := range a.fails {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	a.fails = kept
	if len(a.fails) >= maxFailsWindow {
		a.mu.Unlock()
		return "", time.Time{}, apiError(429, "too_many_attempts")
	}
	a.mu.Unlock()
	f, ok := a.load()
	if !ok {
		return "", time.Time{}, apiError(409, "password_not_set")
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(f.Salt)
	want, e2 := base64.RawStdEncoding.DecodeString(f.Hash)
	if e1 != nil || e2 != nil || len(password) > 512 || subtle.ConstantTimeCompare(derive(password, salt, f.Iter), want) != 1 {
		a.mu.Lock()
		a.fails = append(a.fails, a.now())
		a.mu.Unlock()
		return "", time.Time{}, apiError(401, "wrong_password")
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	token := sessionPrefix + base64.RawURLEncoding.EncodeToString(raw)
	exp := now.Add(sessionTTL)
	a.mu.Lock()
	a.sessions[sha256.Sum256([]byte(token))] = exp
	a.mu.Unlock()
	return token, exp, nil
}

func (a *consoleAuth) check(token string) bool {
	if !strings.HasPrefix(token, sessionPrefix) {
		return false
	}
	k := sha256.Sum256([]byte(token))
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[k]
	if !ok {
		return false
	}
	if !a.now().Before(exp) {
		delete(a.sessions, k)
		return false
	}
	return true
}

func (a *consoleAuth) logout(token string) {
	a.mu.Lock()
	delete(a.sessions, sha256.Sum256([]byte(token)))
	a.mu.Unlock()
}

// consolePrincipal is what a password session acts as: the owner.
var consolePrincipal = principal{ID: "console", Scopes: []string{"admin"}, Accounts: []string{"*"}}
