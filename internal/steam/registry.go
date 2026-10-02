package steam

import (
	"math"
	"math/big"
	"regexp"
)

func Registry() map[string]Operation {
	out := map[string]Operation{}
	groups := [][]Operation{PublicOperations(), SessionOperations(), AuthenticatedOperations(), QRApprovalOperations()}
	for _, g := range groups {
		for _, o := range g {
			if _, ok := out[o.Name]; ok {
				panic("duplicate operation")
			}
			out[o.Name] = o
		}
	}
	return out
}
func ValidateArgs(op Operation, args map[string]any) error { return validateSchema(op.Schema, args, 0) }
func schemaError() error                                   { return &APIError{Status: 400, Code: "invalid_arguments"} }
func schemaNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}
func list(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		r := make([]any, len(x))
		for i, v := range x {
			r[i] = v
		}
		return r
	}
	return nil
}
func validateSchema(s map[string]any, v any, depth int) error {
	if depth > 16 {
		return schemaError()
	}
	if values, ok := s["enum"]; ok {
		matched := false
		for _, x := range list(values) {
			if x == v {
				matched = true
			}
		}
		if !matched {
			return schemaError()
		}
	}
	switch s["type"] {
	case "object":
		o, ok := v.(map[string]any)
		if !ok {
			return schemaError()
		}
		props, _ := s["properties"].(map[string]any)
		if props == nil {
			if typed, ok := s["properties"].(map[string]map[string]any); ok {
				props = map[string]any{}
				for k, v := range typed {
					props[k] = v
				}
			}
		}
		for _, key := range list(s["required"]) {
			k, ok := key.(string)
			if !ok {
				return schemaError()
			}
			if _, ok = o[k]; !ok {
				return schemaError()
			}
		}
		for k, val := range o {
			if k == "__proto__" || k == "constructor" || k == "prototype" {
				return schemaError()
			}
			p, ok := props[k]
			if !ok {
				if s["additionalProperties"] == false {
					return schemaError()
				}
				continue
			}
			sub, ok := p.(map[string]any)
			if !ok {
				return schemaError()
			}
			if e := validateSchema(sub, val, depth+1); e != nil {
				return e
			}
		}
	case "string":
		x, ok := v.(string)
		if !ok {
			return schemaError()
		}
		n := float64(len([]rune(x)))
		if bound, ok := schemaNumber(s["minLength"]); ok && n < bound {
			return schemaError()
		}
		if bound, ok := schemaNumber(s["maxLength"]); ok && n > bound {
			return schemaError()
		}
		if p, ok := s["pattern"].(string); ok {
			r, e := regexp.Compile(p)
			if e != nil || !r.MatchString(x) {
				return schemaError()
			}
		}
		if s["format"] == "uint64" {
			if !regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`).MatchString(x) {
				return schemaError()
			}
			n, ok := new(big.Int).SetString(x, 10)
			if !ok || n.BitLen() > 64 {
				return schemaError()
			}
		}
	case "integer", "number":
		n, ok := schemaNumber(v)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
			return schemaError()
		}
		if s["type"] == "integer" && (math.Trunc(n) != n || math.Abs(n) > 9007199254740991) {
			return schemaError()
		}
		if b, ok := schemaNumber(s["minimum"]); ok && n < b {
			return schemaError()
		}
		if b, ok := schemaNumber(s["maximum"]); ok && n > b {
			return schemaError()
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return schemaError()
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return schemaError()
		}
		if b, ok := schemaNumber(s["minItems"]); ok && float64(len(a)) < b {
			return schemaError()
		}
		if b, ok := schemaNumber(s["maxItems"]); ok && float64(len(a)) > b {
			return schemaError()
		}
		if sub, ok := s["items"].(map[string]any); ok {
			for _, val := range a {
				if e := validateSchema(sub, val, depth+1); e != nil {
					return e
				}
			}
		}
	case "null":
		if v != nil {
			return schemaError()
		}
	default:
		return schemaError()
	}
	return nil
}
