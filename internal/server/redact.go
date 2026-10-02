package server

import (
	"errors"
	"strings"
)

func safeRun(run func(map[string]any) (any, error), state map[string]any) (result any, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = errors.New("operation panic")
		}
	}()
	return run(state)
}
func redactJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			secret := false
			for _, word := range secretWords {
				if strings.Contains(strings.ToLower(k), word) {
					secret = true
					break
				}
			}
			if !secret {
				out[k] = redactJSON(x)
			}
		}
		return out
	case []any:
		for i, x := range v {
			v[i] = redactJSON(x)
		}
		return v
	default:
		return value
	}
}
