package server

import (
	"testing"
)

// A definitive upstream 4xx verdict (e.g. Steam eresult 5 InvalidPassword, which
// transport maps to 403) must surface its real code, not outcome_unknown.
// Uncertain outcomes (5xx, 429) still fold to outcome_unknown, and the intent
// must never be re-executed in either case.
func TestDefinitiveRejectionSurfacesRealCode(t *testing.T) {
	if !definitiveRejection(apiError(403, "upstream_eresult_5")) {
		t.Fatal("403 eresult verdict should be definitive")
	}
	if definitiveRejection(apiError(502, "upstream_invalid_response")) {
		t.Fatal("5xx is uncertain, not definitive")
	}
	if definitiveRejection(apiError(429, "upstream_rate_limited")) {
		t.Fatal("429 is uncertain, not definitive")
	}
	if definitiveRejection(apiError(500, "internal_error")) {
		t.Fatal("500 is uncertain, not definitive")
	}
}
