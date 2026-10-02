package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// strictObject rejects duplicate keys, prototype-shaped keys and excessive nesting.
func strictObject(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	value, e := jsonValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, errors.New("object required")
	}
	return object, nil
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("JSON too deep")
	}
	token, e := d.Token()
	if e != nil {
		return nil, e
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return nil, e
			}
			k, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid key")
			}
			if _, exists := m[k]; exists || k == "__proto__" || k == "constructor" || k == "prototype" {
				return nil, errors.New("invalid key")
			}
			value, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[k] = value
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object")
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			value, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, value)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array")
		}
		return a, nil
	default:
		return nil, errors.New("invalid JSON")
	}
}
