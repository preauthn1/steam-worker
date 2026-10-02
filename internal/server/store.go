package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type httpError struct {
	Status int
	Code   string
}

func (e *httpError) Error() string           { return e.Code }
func apiError(status int, code string) error { return &httpError{status, code} }
func errorCode(err error) string {
	var e *httpError
	if errors.As(err, &e) {
		return e.Code
	}
	return "internal_error"
}

type accountRecord struct {
	Format  string         `json:"format"`
	Exists  bool           `json:"exists"`
	State   map[string]any `json:"state"`
	Version uint64         `json:"version"`
	Rate    struct {
		Minute int64 `json:"minute"`
		Count  int   `json:"count"`
	} `json:"rate"`
}
type intent struct {
	Digest        string `json:"digest"`
	Status        string `json:"status"`
	Operation     string `json:"operation"`
	CreatedAt     int64  `json:"created_at"`
	Result        any    `json:"result,omitempty"`
	ResultOmitted bool   `json:"result_omitted,omitempty"`
	ErrorStatus   int    `json:"error_status,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
}
type store struct {
	db    *bolt.DB
	key   string
	locks sync.Map
	clock func() int64
}

func openStore(path, key string) (*store, error) {
	if _, err := newVault(key, "check"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db, key: key, clock: func() int64 { return time.Now().Unix() }}, nil
}
func (s *store) Close() error { return s.db.Close() }
func (s *store) lock(account string) func() {
	m, _ := s.locks.LoadOrStore(account, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
func (s *store) load(account string) (*accountRecord, error) {
	r := &accountRecord{Format: "steam-go-v1", State: map[string]any{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(account))
		if b == nil {
			return nil
		}
		v, _ := newVault(s.key, account)
		raw := b.Get([]byte("state"))
		if raw == nil {
			return errors.New("missing state")
		}
		if err := v.open(string(raw), r); err != nil {
			return err
		}
		if r.Format != "steam-go-v1" || r.State == nil {
			return errors.New("incompatible state")
		}
		return nil
	})
	return r, err
}
func (s *store) save(account string, r *accountRecord, slot string, i *intent) error {
	v, _ := newVault(s.key, account)
	state, err := v.seal(r)
	if err != nil {
		return err
	}
	var journal string
	if i != nil {
		copy := *i
		raw, err := json.Marshal(copy.Result)
		if err != nil {
			return err
		}
		if len(raw) > 16384 {
			copy.Result = nil
			copy.ResultOmitted = true
		}
		journal, err = v.seal(copy)
		if err != nil {
			return err
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(account))
		if err != nil {
			return err
		}
		if err = b.Put([]byte("state"), []byte(state)); err != nil {
			return err
		}
		if i != nil {
			return b.Put([]byte("intent:"+slot), []byte(journal))
		}
		return nil
	})
}
func digest(v string) string { x := sha256.Sum256([]byte(v)); return hex.EncodeToString(x[:]) }
func (s *store) prepare(account, principal, key, op string, args map[string]any) (string, *intent, bool, error) {
	slot := digest(principal + "\x00" + key)
	raw, err := json.Marshal([]any{op, args})
	if err != nil {
		return "", nil, false, apiError(400, "invalid_arguments")
	}
	d := digest("steam-go-journal-v1\x00" + string(raw))
	var i *intent
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(account))
		if b == nil {
			return nil
		}
		saved := b.Get([]byte("intent:" + slot))
		if saved == nil {
			return nil
		}
		i = &intent{}
		v, _ := newVault(s.key, account)
		return v.open(string(saved), i)
	})
	if err != nil {
		return "", nil, false, err
	}
	if i != nil {
		if i.Digest != d {
			return "", nil, false, apiError(409, "idempotency_conflict")
		}
		if i.Status == "rejected" {
			return "", nil, false, apiError(i.ErrorStatus, i.ErrorCode)
		}
		if i.Status != "succeeded" {
			return "", nil, false, apiError(409, "outcome_unknown")
		}
		if i.ResultOmitted {
			return "", nil, false, apiError(409, "succeeded_result_not_cached")
		}
		return slot, i, true, nil
	}
	return slot, &intent{Digest: d, Status: "prepared", Operation: op, CreatedAt: s.clock()}, false, nil
}
func (s *store) limit(r *accountRecord) error {
	minute := s.clock() / 60
	if r.Rate.Minute != minute {
		r.Rate.Minute = minute
		r.Rate.Count = 0
	}
	if r.Rate.Count >= 30 {
		return apiError(429, "rate_limited")
	}
	r.Rate.Count++
	return nil
}
func meta(r *accountRecord) any { return map[string]any{"exists": r.Exists, "version": r.Version} }
func (s *store) info(account string) (any, error) {
	defer s.lock(account)()
	r, e := s.load(account)
	if e != nil {
		return nil, e
	}
	if !r.Exists {
		return nil, apiError(404, "account_not_found")
	}
	return meta(r), nil
}
func (s *store) accounts() ([]string, error) {
	all := []string{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			v, _ := newVault(s.key, string(name))
			var r accountRecord
			if err := v.open(string(b.Get([]byte("state"))), &r); err != nil {
				return err
			}
			if r.Format != "steam-go-v1" {
				return errors.New("incompatible state")
			}
			if r.Exists {
				all = append(all, string(name))
			}
			return nil
		})
	})
	sort.Strings(all)
	return all, err
}
func (s *store) manage(account, action string, args map[string]any, principal, key string) (any, error) {
	defer s.lock(account)()
	r, e := s.load(account)
	if e != nil {
		return nil, e
	}
	v, _ := newVault(s.key, account)
	if action == "import" {
		if len(args) != 1 {
			return nil, apiError(400, "invalid_state")
		}
		if envelope, ok := args["envelope"].(string); ok {
			var imported map[string]any
			if v.open(envelope, &imported) != nil {
				return nil, apiError(400, "invalid_envelope")
			}
			args = imported
		}
		if len(args) != 1 {
			return nil, apiError(400, "invalid_state")
		}
		if state, ok := args["state"].(map[string]any); !ok || state == nil {
			return nil, apiError(400, "invalid_state")
		}
	}
	if action != "import" && len(args) != 0 {
		return nil, apiError(400, "unexpected_arguments")
	}
	slot, i, replay, e := s.prepare(account, principal, key, "account."+action, args)
	if e != nil {
		return nil, e
	}
	if replay {
		if action == "export" {
			return i.Result, nil
		}
		return meta(r), nil
	}
	fail := func(e error) (any, error) {
		i.Status = "rejected"
		var h *httpError
		if errors.As(e, &h) {
			i.ErrorStatus = h.Status
			i.ErrorCode = h.Code
		} else {
			i.ErrorStatus = 500
			i.ErrorCode = "internal_error"
		}
		if se := s.save(account, r, slot, i); se != nil {
			return nil, se
		}
		return nil, e
	}
	if action == "create" && r.Exists {
		return fail(apiError(409, "account_exists"))
	}
	if action != "create" && !r.Exists {
		return fail(apiError(404, "account_not_found"))
	}
	if e = s.limit(r); e != nil {
		return fail(e)
	}
	var result any
	switch action {
	case "create":
		r.Exists = true
		r.State = map[string]any{}
		r.Version++
		result = meta(r)
	case "delete":
		r.Exists = false
		r.State = map[string]any{}
		r.Version++
		result = meta(r)
	case "import":
		r.State = args["state"].(map[string]any)
		r.Version++
		result = meta(r)
	case "export":
		envelope, e := v.seal(map[string]any{"state": r.State})
		if e != nil {
			return fail(e)
		}
		result = map[string]any{"format": "steam-worker-state-v1", "envelope": envelope}
	default:
		return fail(apiError(404, "not_found"))
	}
	i.Status = "succeeded"
	i.Result = result
	if e = s.save(account, r, slot, i); e != nil {
		return nil, e
	}
	return result, nil
}
func (s *store) execute(account, op string, args map[string]any, principal, key string, mutating bool, run func(map[string]any) (any, error), requests func() int) (any, error) {
	defer s.lock(account)()
	r, e := s.load(account)
	if e != nil {
		return nil, e
	}
	if !r.Exists {
		return nil, apiError(404, "account_not_found")
	}
	var i *intent
	slot := ""
	if mutating {
		var replay bool
		slot, i, replay, e = s.prepare(account, principal, key, op, args)
		if e != nil {
			return nil, e
		}
		if replay {
			return i.Result, nil
		}
	}
	if e = s.limit(r); e != nil {
		if i != nil {
			i.Status = "rejected"
			i.ErrorStatus = 429
			i.ErrorCode = "rate_limited"
			if se := s.save(account, r, slot, i); se != nil {
				return nil, se
			}
		}
		return nil, e
	}
	if i != nil {
		i.Status = "in_flight"
	}
	if e = s.save(account, r, slot, i); e != nil {
		return nil, e
	}
	result, e := safeRun(run, r.State)
	if e != nil {
		if i != nil {
			var h *httpError
			if errors.As(e, &h) && requests() == 0 {
				i.Status = "rejected"
				i.ErrorStatus = h.Status
				i.ErrorCode = h.Code
			} else {
				// Outcome stays unknown (never auto-retried), but a definitive
				// upstream judgment (4xx other than 429: e.g. Steam eresult 5
				// InvalidPassword) is surfaced truthfully to the caller instead
				// of being folded into outcome_unknown.
				i.Status = "unknown"
				if !definitiveRejection(e) {
					e = apiError(409, "outcome_unknown")
				}
			}
		}
		if se := s.save(account, r, slot, i); se != nil {
			return nil, se
		}
		if i == nil {
			var h *httpError
			if !errors.As(e, &h) {
				e = apiError(502, "upstream_failed")
			}
		}
		return nil, e
	}
	result = redact(result)
	r.Version++
	if i != nil {
		i.Status = "succeeded"
		i.Result = result
	}
	if e = s.save(account, r, slot, i); e != nil {
		if i != nil {
			return nil, apiError(409, "outcome_unknown")
		}
		return nil, e
	}
	return result, nil
}

var secretWords = []string{"password", "secret", "token", "cookie", "authorization", "signature", "revocation", "recovery", "auth_code", "apikey", "api_key", "request_id", "client_id", "mafile", "wallet_code"}

// definitiveRejection reports whether err is a definitive upstream verdict that
// the requested action was refused (HTTP 4xx other than 429), rather than an
// uncertain transport outcome. Replaying a refused request cannot double-apply
// an effect, so surfacing the verdict does not weaken the no-retry guarantee:
// the intent remains status=unknown and is never re-executed.
func definitiveRejection(err error) bool {
	var h *httpError
	return errors.As(err, &h) && h.Status >= 400 && h.Status < 500 && h.Status != 429
}

func redact(value any) any {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return nil
	}
	return redactJSON(decoded)
}
