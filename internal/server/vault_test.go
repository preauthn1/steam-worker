package server

import (
	"strings"
	"testing"
)

func TestVaultPythonVector(t *testing.T) {
	v, e := newVault(strings.Repeat("11", 32), "alpha")
	if e != nil {
		t.Fatal(e)
	}
	var got map[string]any
	if e = v.open("z9AvTlJbpdDaGZ3UqSx1+PtI3QpWzd6SbbEX+Y/sh4UsdeY=", &got); e != nil || got["a"] != float64(1) {
		t.Fatalf("vector: %v %v", got, e)
	}
	a, e := v.seal(map[string]any{"password": "synthetic-secret"})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := v.seal(map[string]any{"password": "synthetic-secret"})
	if a == b || strings.Contains(a, "synthetic-secret") {
		t.Fatal("not encrypted/randomized")
	}
	other, _ := newVault(strings.Repeat("11", 32), "beta")
	if other.open(a, &got) == nil {
		t.Fatal("cross account accepted")
	}
	if v.open(a[:len(a)-4]+"AAAA", &got) == nil {
		t.Fatal("tamper accepted")
	}
}
