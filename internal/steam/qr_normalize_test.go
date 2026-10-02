package steam

import "testing"

func TestNormalizeQRInput(t *testing.T) {
	base := "https://s.team/q/1/11599465637103800067"
	cases := map[string]string{
		base:                          base,
		base + " ":                    base,
		" " + base:                    base,
		base + "\n":                   base,
		base + "\u3000":               base,
		base + "\u200b":               base,
		"\ufeff" + base + "\u2060":    base,
		"\"" + base + "\"":            base,
		"\u201c" + base + "\u201d":    base,
		"<" + base + ">":              base,
		base + "\u00a0":               base,
		// interior pollution stays rejected (normalizer must not touch middle)
		"https://s.team/q/1 /123":     "https://s.team/q/1 /123",
		"":                            "",
	}
	for in, want := range cases {
		if got := normalizeQRInput(in); got != want {
			t.Fatalf("normalize(%q)=%q want %q", in, got, want)
		}
	}
	// end-to-end: polluted input passes qrChallenge
	if _, _, e := qrChallenge(" " + base + "\u3000"); e != nil {
		t.Fatal("polluted URL rejected after normalization:", e)
	}
	if _, _, e := qrChallenge("https://s.team/q/1/12 3"); e == nil {
		t.Fatal("interior-polluted URL must stay rejected")
	}
}
