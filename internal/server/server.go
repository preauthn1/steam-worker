package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/preauthn1/steam-worker/internal/steam"
)

type Config struct {
	APIKeysJSON, StateKeyHex, DataDir string
	Registry                          map[string]steam.Operation
	HTML                              []byte
	CSP                               string
}
type principal struct {
	ID       string   `json:"id"`
	SHA256   string   `json:"sha256"`
	Scopes   []string `json:"scopes"`
	Accounts []string `json:"accounts"`
	hash     []byte
}
type Server struct {
	store *store
	keys  []principal
	ops   map[string]steam.Operation
	html  []byte
	csp   string
}

var slug = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var idem = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var accountRoute = regexp.MustCompile(`^/v1/accounts/([a-zA-Z0-9][a-zA-Z0-9_-]{0,63})(?:/(import|export|operations/([a-zA-Z0-9_.-]{1,150})))?$`)

func contains(v []string, x string) bool {
	for _, a := range v {
		if a == x {
			return true
		}
	}
	return false
}
func New(c Config) (http.Handler, error) {
	var keys []principal
	if json.Unmarshal([]byte(c.APIKeysJSON), &keys) != nil || len(keys) == 0 {
		return nil, errors.New("configuration_missing")
	}
	ids := map[string]bool{}
	for i := range keys {
		p := &keys[i]
		if !slug.MatchString(p.ID) || ids[p.ID] || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.SHA256) || p.Scopes == nil || p.Accounts == nil {
			return nil, errors.New("configuration_missing")
		}
		ids[p.ID] = true
		p.hash, _ = hex.DecodeString(p.SHA256)
		for _, scope := range p.Scopes {
			if scope != "read" && scope != "write" && scope != "admin" {
				return nil, errors.New("configuration_missing")
			}
		}
		for _, a := range p.Accounts {
			if a != "*" && !slug.MatchString(a) {
				return nil, errors.New("configuration_missing")
			}
		}
	}
	if c.DataDir == "" {
		return nil, errors.New("configuration_missing")
	}
	if c.HTML == nil {
		c.HTML, c.CSP = Assets()
	}
	if len(c.HTML) == 0 || c.CSP == "" || strings.ContainsAny(c.CSP, "\r\n") {
		return nil, errors.New("configuration_missing")
	}
	ops := c.Registry
	if ops == nil {
		ops = steam.Registry()
	}
	copyOps := map[string]steam.Operation{}
	for name, op := range ops {
		if name != op.Name || op.Run == nil || op.Scope != "read" && op.Scope != "write" && op.Scope != "admin" || op.Mutating && op.Scope == "read" {
			return nil, errors.New("invalid_operation_policy")
		}
		copyOps[name] = op
	}
	s, e := openStore(filepath.Join(c.DataDir, "state.db"), c.StateKeyHex)
	if e != nil {
		return nil, e
	}
	return &Server{s, keys, copyOps, append([]byte(nil), c.HTML...), c.CSP}, nil
}
func (s *Server) Close() error { return s.store.Close() }
func (s *Server) auth(r *http.Request, account, scope string) (principal, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || len(h)-7 < 32 || len(h)-7 > 512 {
		return principal{}, apiError(401, "unauthorized")
	}
	hash := sha256.Sum256([]byte(h[7:]))
	for _, p := range s.keys {
		if subtle.ConstantTimeCompare(p.hash, hash[:]) == 1 {
			if !contains(p.Scopes, scope) && !contains(p.Scopes, "admin") {
				return p, apiError(403, "scope_denied")
			}
			if account != "" && !contains(p.Accounts, account) && !(contains(p.Scopes, "admin") && contains(p.Accounts, "*")) {
				return p, apiError(403, "account_denied")
			}
			return p, nil
		}
	}
	return principal{}, apiError(401, "unauthorized")
}
func reply(w http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		status = 500
		raw = []byte(`{"error":{"code":"internal_error"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(raw)
}
func publicError(err error) error {
	var a *steam.APIError
	if errors.As(err, &a) {
		if a.Status >= 400 && a.Status <= 599 && regexp.MustCompile(`^[a-z][a-z0-9_]{0,100}$`).MatchString(a.Code) {
			return apiError(a.Status, a.Code)
		}
		return apiError(502, "upstream_failed")
	}
	var h *httpError
	if errors.As(err, &h) {
		return h
	}
	return errors.New("upstream_failed")
}
func readBody(r *http.Request) (map[string]any, error) {
	if r.ContentLength > 131072 {
		return nil, apiError(413, "body_too_large")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 131073))
	if e != nil {
		return nil, apiError(400, "invalid_json")
	}
	if len(raw) > 131072 {
		return nil, apiError(413, "body_too_large")
	}
	if !utf8.Valid(raw) {
		return nil, apiError(400, "invalid_json")
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	value, err := strictObject(raw)
	if err != nil {
		return nil, apiError(400, "invalid_json")
	}
	return value, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	result, e := s.handle(w, r)
	if e != nil {
		var h *httpError
		if !errors.As(e, &h) {
			h = &httpError{500, "internal_error"}
		}
		reply(w, h.Status, map[string]any{"error": map[string]any{"code": h.Code}})
		return
	}
	if result != nil {
		reply(w, 200, result)
	}
}
func (s *Server) handle(w http.ResponseWriter, r *http.Request) (any, error) {
	path := r.URL.Path
	if path == "/" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", s.csp)
		w.Write(s.html)
		return nil, nil
	}
	if path == "/health" && r.Method == "GET" {
		return map[string]any{"ok": true}, nil
	}
	action, account, opName := "", "", ""
	scope := "admin"
	mutating := false
	switch path {
	case "/v1/operations":
		if r.Method != "GET" {
			return nil, apiError(405, "method_not_allowed")
		}
		action = "catalog"
		scope = "read"
	case "/v1/accounts":
		if r.Method != "GET" {
			return nil, apiError(405, "method_not_allowed")
		}
		action = "list"
	default:
		m := accountRoute.FindStringSubmatch(path)
		if m == nil {
			return nil, apiError(404, "not_found")
		}
		account = m[1]
		opName = m[3]
		if opName != "" {
			if r.Method != "POST" {
				return nil, apiError(405, "method_not_allowed")
			}
			action = "operation"
			op, ok := s.ops[opName]
			if !ok {
				return nil, apiError(404, "operation_not_found")
			}
			scope = op.Scope
			mutating = op.Mutating
		} else if m[2] != "" {
			if r.Method != "POST" {
				return nil, apiError(405, "method_not_allowed")
			}
			action = m[2]
			mutating = true
		} else {
			switch r.Method {
			case "GET":
				action = "info"
				scope = "read"
			case "PUT":
				action = "create"
				mutating = true
			case "DELETE":
				action = "delete"
				mutating = true
			default:
				return nil, apiError(405, "method_not_allowed")
			}
		}
	}
	p, e := s.auth(r, account, scope)
	if e != nil {
		return nil, e
	}
	key := ""
	if mutating {
		if r.Header.Get("X-Confirm-Write") != "true" {
			return nil, apiError(428, "write_confirmation_required")
		}
		key = r.Header.Get("Idempotency-Key")
		if !idem.MatchString(key) {
			return nil, apiError(400, "idempotency_key_required")
		}
	}
	switch action {
	case "catalog":
		names := []string{}
		for name := range s.ops {
			names = append(names, name)
		}
		sort.Strings(names)
		out := []any{}
		for _, name := range names {
			o := s.ops[name]
			out = append(out, map[string]any{"name": o.Name, "scope": o.Scope, "mutating": o.Mutating, "description": o.Description, "schema": o.Schema})
		}
		return map[string]any{"operations": out}, nil
	case "list":
		all, e := s.store.accounts()
		if e != nil {
			return nil, e
		}
		visible := []string{}
		for _, a := range all {
			if contains(p.Accounts, a) || contains(p.Scopes, "admin") && contains(p.Accounts, "*") {
				visible = append(visible, a)
			}
		}
		return map[string]any{"accounts": visible}, nil
	case "info":
		return s.store.info(account)
	}
	args, e := readBody(r)
	if e != nil {
		return nil, e
	}
	if action != "operation" {
		return s.store.manage(account, action, args, p.ID, key)
	}
	for k := range args {
		if k != "arguments" {
			return nil, apiError(400, "invalid_arguments")
		}
	}
	values := map[string]any{}
	if x, exists := args["arguments"]; exists {
		var ok bool
		values, ok = x.(map[string]any)
		if !ok || values == nil {
			return nil, apiError(400, "invalid_arguments")
		}
	}
	op := s.ops[opName]
	if e = steam.ValidateArgs(op, values); e != nil {
		return nil, publicError(e)
	}
	t := steam.NewTransport()
	effective := "read"
	if contains(p.Scopes, "admin") {
		effective = "admin"
	} else if contains(p.Scopes, "write") {
		effective = "write"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, e := s.store.execute(account, opName, values, p.ID, key, mutating, func(state map[string]any) (any, error) {
		c := &steam.Context{State: steam.State(state), Transport: t, Scope: effective}
		if e := steam.LoadCookies(t, c.State); e != nil {
			return nil, publicError(e)
		}
		defer steam.SaveCookies(t, c.State)
		v, e := op.Run(ctx, c, values)
		if e != nil {
			return nil, publicError(e)
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		return v, nil
	}, t.Count)
	if e != nil {
		return nil, e
	}
	return map[string]any{"result": result}, nil
}
