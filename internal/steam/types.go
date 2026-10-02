package steam

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type State map[string]any
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string        { return e.Code }
func fail(status int, code string) error { return &APIError{status, code} }
func invalidResponse() error             { return fail(502, "upstream_invalid_response") }

type Response struct {
	Status  int
	URL     string
	Headers http.Header
	Body    []byte
}
type Context struct {
	State     State
	Transport *Transport
	Scope     string
}
type Operation struct {
	Name        string                                                       `json:"name"`
	Scope       string                                                       `json:"scope"`
	Mutating    bool                                                         `json:"mutating"`
	Description string                                                       `json:"description"`
	Schema      map[string]any                                               `json:"schema"`
	Run         func(context.Context, *Context, map[string]any) (any, error) `json:"-"`
}

func object(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return x
	case State:
		return map[string]any(x)
	}
	return nil
}
func textValue(v any) string { s, _ := v.(string); return s }
func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case uint64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func decimal(v any) uint64 { n, _ := strconv.ParseUint(textValue(v), 10, 64); return n }
func timestamp() float64   { return float64(time.Now().UnixNano()) / 1e9 }
func schema(props map[string]any, required []string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": required}
}
func strSchema(max int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": max}
}
