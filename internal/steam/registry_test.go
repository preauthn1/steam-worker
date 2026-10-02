package steam

import "testing"

func TestSchemaCanonicalIDsAndNestedBounds(t *testing.T) {
	op := Operation{Schema: map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string", "format": "uint64"}, "amount": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}}}
	if e := ValidateArgs(op, map[string]any{"id": "18446744073709551615"}); e != nil {
		t.Fatal(e)
	}
	for _, a := range []map[string]any{{"id": "01"}, {"id": "18446744073709551616"}, {"id": "1", "amount": 101.0}, {"id": "1", "extra": true}, {"id": "1", "__proto__": map[string]any{}}} {
		if e := ValidateArgs(op, a); e == nil {
			t.Fatalf("accepted invalid arguments %#v", a)
		}
	}
}
func TestRegistryPreservesOperationCountAndPolicy(t *testing.T) {
	r := Registry()
	if len(r) != 38 {
		t.Fatalf("operations %d want38", len(r))
	}
	for name, o := range r {
		if name != o.Name || o.Run == nil {
			t.Fatalf("invalid operation %s", name)
		}
		if o.Mutating && o.Scope == "read" {
			t.Fatalf("invalid policy %s", name)
		}
	}
}
