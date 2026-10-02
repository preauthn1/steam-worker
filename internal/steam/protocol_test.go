package steam

import (
	"bytes"
	"testing"
)

func TestProtocolRoundtrip(t *testing.T) {
	b := new(ProtoWriter).Uint(1, ^uint64(0)).Fixed64(2, 42).String(3, "synthetic").Bool(4, true).Finish()
	m, e := DecodeProto(b)
	if e != nil || m[1][0].Uint != ^uint64(0) || m[2][0].Uint != 42 || !bytes.Equal(m[3][0].Bytes, []byte("synthetic")) {
		t.Fatalf("roundtrip: %v", e)
	}
	for _, bad := range [][]byte{{8, 128}, {18, 5, 1}, {9, 1}, {15}, {8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2}} {
		if _, e := DecodeProto(bad); e == nil {
			t.Fatal("accepted malformed protobuf")
		}
	}
}
func TestGuardVectors(t *testing.T) {
	s := "AAAAAAAAAAAAAAAAAAAAAAAAAAA="
	a, e := GenerateAuthCode(s, 0)
	if e != nil || len(a) != 5 {
		t.Fatal(a, e)
	}
	b, e := GenerateConfirmationKey(s, "conf", 0)
	if e != nil || len(b) != 28 {
		t.Fatal(b, e)
	}
	if _, e := GenerateAuthCode("invalid", 0); e == nil {
		t.Fatal("invalid secret accepted")
	}
}
