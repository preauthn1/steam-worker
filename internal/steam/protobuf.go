package steam

import (
	"encoding/binary"
	"errors"
)

type ProtoWriter struct{ buf []byte }

func (w *ProtoWriter) Uint(f int, v uint64) *ProtoWriter {
	w.buf = binary.AppendUvarint(w.buf, uint64(f)<<3)
	w.buf = binary.AppendUvarint(w.buf, v)
	return w
}
func (w *ProtoWriter) Bytes(f int, v []byte) *ProtoWriter {
	w.buf = binary.AppendUvarint(w.buf, uint64(f)<<3|2)
	w.buf = binary.AppendUvarint(w.buf, uint64(len(v)))
	w.buf = append(w.buf, v...)
	return w
}
func (w *ProtoWriter) String(f int, v string) *ProtoWriter { return w.Bytes(f, []byte(v)) }
func (w *ProtoWriter) Bool(f int, v bool) *ProtoWriter {
	var n uint64
	if v {
		n = 1
	}
	return w.Uint(f, n)
}
func (w *ProtoWriter) Fixed64(f int, v uint64) *ProtoWriter {
	w.buf = binary.AppendUvarint(w.buf, uint64(f)<<3|1)
	w.buf = binary.LittleEndian.AppendUint64(w.buf, v)
	return w
}
func (w *ProtoWriter) Finish() []byte { return append([]byte(nil), w.buf...) }

type ProtoField struct {
	Wire  int
	Uint  uint64
	Bytes []byte
}

func DecodeProto(b []byte) (map[int][]ProtoField, error) {
	m := map[int][]ProtoField{}
	bad := errors.New("invalid protobuf")
	for len(b) > 0 {
		k, n := binary.Uvarint(b)
		if n <= 0 || k>>3 == 0 || k>>3 > 536870911 {
			return nil, bad
		}
		b = b[n:]
		f := ProtoField{Wire: int(k & 7)}
		switch f.Wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, bad
			}
			f.Uint = v
			b = b[n:]
		case 1, 5:
			n := 8
			if f.Wire == 5 {
				n = 4
			}
			if len(b) < n {
				return nil, bad
			}
			if n == 8 {
				f.Uint = binary.LittleEndian.Uint64(b)
			} else {
				f.Uint = uint64(binary.LittleEndian.Uint32(b))
			}
			b = b[n:]
		case 2:
			v, n := binary.Uvarint(b)
			if n <= 0 || v > uint64(len(b)-n) {
				return nil, bad
			}
			b = b[n:]
			f.Bytes = append([]byte{}, b[:int(v)]...)
			b = b[int(v):]
		default:
			return nil, bad
		}
		id := int(k >> 3)
		m[id] = append(m[id], f)
	}
	return m, nil
}
func protoInt(m map[int][]ProtoField, f int) uint64 {
	if len(m[f]) > 0 {
		return m[f][0].Uint
	}
	return 0
}
func protoBytes(m map[int][]ProtoField, f int) []byte {
	if len(m[f]) > 0 {
		return m[f][0].Bytes
	}
	return nil
}
func protoString(m map[int][]ProtoField, f int) string { return string(protoBytes(m, f)) }
