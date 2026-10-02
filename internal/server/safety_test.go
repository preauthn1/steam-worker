package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntentBeforeRunAndPanicRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := openStore(path, strings.Repeat("33", 32))
	if e != nil {
		t.Fatal(e)
	}
	s.manage("alpha", "create", map[string]any{}, "p", "create-key-00001")
	_, e = s.execute("alpha", "panic", map[string]any{}, "p", "panic-key-000001", true, func(state map[string]any) (any, error) {
		_, _, _, e := s.prepare("alpha", "p", "panic-key-000001", "panic", map[string]any{})
		if errorCode(e) != "outcome_unknown" {
			t.Fatal("intent not durable before run", e)
		}
		state["password"] = "synthetic-private-marker"
		panic("secret panic")
	}, func() int { return 0 })
	if errorCode(e) != "outcome_unknown" {
		t.Fatal(e)
	}
	s.Close()
	data, e := os.ReadFile(path)
	if e != nil || bytes.Contains(data, []byte("synthetic-private-marker")) || bytes.Contains(data, []byte(`"status":"unknown"`)) {
		t.Fatal("plaintext persisted", e)
	}
	s, e = openStore(path, strings.Repeat("33", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, e := s.load("alpha")
	if e != nil || r.State["password"] != "synthetic-private-marker" {
		t.Fatal("panic state lost", e)
	}
	_, e = s.execute("alpha", "panic", map[string]any{}, "p", "panic-key-000001", true, func(map[string]any) (any, error) { t.Fatal("retry"); return nil, nil }, func() int { return 0 })
	if errorCode(e) != "outcome_unknown" {
		t.Fatal(e)
	}
	slot, i, _, e := s.prepare("alpha", "p", "crash-key-000001", "crash", map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	i.Status = "in_flight"
	if e = s.save("alpha", r, slot, i); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = openStore(path, strings.Repeat("33", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, _, _, e = s.prepare("alpha", "p", "crash-key-000001", "crash", map[string]any{})
	if errorCode(e) != "outcome_unknown" {
		t.Fatal("inflight resumed", e)
	}
}
func TestPerAccountLock(t *testing.T) {
	s, e := openStore(filepath.Join(t.TempDir(), "state.db"), strings.Repeat("44", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, a := range []string{"alpha", "beta"} {
		if _, e = s.manage(a, "create", map[string]any{}, "p", "create-key-00001"); e != nil {
			t.Fatal(e)
		}
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.execute("alpha", "slow", map[string]any{}, "p", "slow-key-0000001", true, func(map[string]any) (any, error) { close(entered); <-release; return nil, nil }, func() int { return 0 })
	}()
	<-entered
	beta := make(chan error, 1)
	go func() {
		_, e := s.execute("beta", "fast", map[string]any{}, "p", "fast-key-0000001", true, func(map[string]any) (any, error) { return nil, nil }, func() int { return 0 })
		beta <- e
	}()
	select {
	case e := <-beta:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("global network lock")
	}
	close(release)
	<-done
}
func TestManagementFailureAndCurrentReplay(t *testing.T) {
	s, e := openStore(filepath.Join(t.TempDir(), "state.db"), strings.Repeat("55", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.manage("alpha", "delete", map[string]any{}, "p", "delete-key-00001"); errorCode(e) != "account_not_found" {
		t.Fatal(e)
	}
	s.manage("alpha", "create", map[string]any{}, "p", "create-key-00001")
	if _, e = s.manage("alpha", "delete", map[string]any{}, "p", "delete-key-00001"); errorCode(e) != "account_not_found" {
		t.Fatal("rejected retry", e)
	}
	s.manage("alpha", "delete", map[string]any{}, "p", "delete-key-00002")
	result, e := s.manage("alpha", "create", map[string]any{}, "p", "create-key-00001")
	if e != nil || result.(map[string]any)["exists"] != false {
		t.Fatal("stale management replay", result, e)
	}
}
