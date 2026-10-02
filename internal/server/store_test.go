package server

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurableJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := openStore(path, strings.Repeat("22", 32))
	if e != nil {
		t.Fatal(e)
	}
	s.clock = func() int64 { return 120 }
	if _, e = s.manage("alpha", "create", map[string]any{}, "p", "create-key-000001"); e != nil {
		t.Fatal(e)
	}
	runs := 0
	run := func(state map[string]any) (any, error) {
		runs++
		state["pending"] = true
		return map[string]any{"safe": true, "access_token": "synthetic"}, nil
	}
	first, e := s.execute("alpha", "x", map[string]any{}, "p", "execute-key-0001", true, run, func() int { return 1 })
	if e != nil {
		t.Fatal(e)
	}
	if first.(map[string]any)["access_token"] != nil {
		t.Fatal("secret exposed")
	}
	s.Close()
	s, e = openStore(path, strings.Repeat("22", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.clock = func() int64 { return 120 }
	if _, e = s.execute("alpha", "x", map[string]any{}, "p", "execute-key-0001", true, run, func() int { return 1 }); e != nil || runs != 1 {
		t.Fatalf("replay %d %v", runs, e)
	}
	if _, e = s.execute("alpha", "x", map[string]any{"a": 1}, "p", "execute-key-0001", true, run, func() int { return 1 }); errorCode(e) != "idempotency_conflict" {
		t.Fatal(e)
	}
	_, e = s.execute("alpha", "fail", map[string]any{}, "p", "unknown-key-0001", true, func(state map[string]any) (any, error) {
		runs++
		state["failure_state"] = "saved"
		return nil, errors.New("secret upstream error")
	}, func() int { return 1 })
	if errorCode(e) != "outcome_unknown" {
		t.Fatal(e)
	}
	if _, e = s.execute("alpha", "fail", map[string]any{}, "p", "unknown-key-0001", true, run, func() int { return 1 }); errorCode(e) != "outcome_unknown" || runs != 2 {
		t.Fatal(e, runs)
	}
	r, e := s.load("alpha")
	if e != nil || r.State["failure_state"] != "saved" {
		t.Fatal(r, e)
	}
	_, e = s.execute("alpha", "reject", map[string]any{}, "p", "rejected-key-001", true, func(state map[string]any) (any, error) {
		state["preflight"] = true
		return nil, apiError(400, "invalid_arguments")
	}, func() int { return 0 })
	if errorCode(e) != "invalid_arguments" {
		t.Fatal(e)
	}
	_, e = s.execute("alpha", "reject", map[string]any{}, "p", "rejected-key-001", true, run, func() int { return 0 })
	if errorCode(e) != "invalid_arguments" {
		t.Fatal(e)
	}
	_, e = s.execute("alpha", "huge", map[string]any{}, "p", "huge-result-key1", true, func(map[string]any) (any, error) { return map[string]any{"safe": strings.Repeat("a", 17000)}, nil }, func() int { return 1 })
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.execute("alpha", "huge", map[string]any{}, "p", "huge-result-key1", true, run, func() int { return 1 })
	if errorCode(e) != "succeeded_result_not_cached" {
		t.Fatal(e)
	}
	for i := 0; i < 25; i++ {
		if _, e = s.execute("alpha", "read", map[string]any{}, "p", "", false, func(map[string]any) (any, error) { return nil, nil }, func() int { return 0 }); e != nil {
			t.Fatal(i, e)
		}
	}
	if _, e = s.execute("alpha", "read", map[string]any{}, "p", "", false, run, func() int { return 0 }); errorCode(e) != "rate_limited" {
		t.Fatal(e)
	}
	s.Close()
	s, e = openStore(path, strings.Repeat("22", 32))
	if e != nil {
		t.Fatal(e)
	}
	s.clock = func() int64 { return 120 }
	defer s.Close()
	if _, e = s.execute("alpha", "read", map[string]any{}, "p", "", false, run, func() int { return 0 }); errorCode(e) != "rate_limited" {
		t.Fatal("rate lost", e)
	}
}
