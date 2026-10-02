package steam

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

func guardMAC(secret string, msg []byte) ([]byte, error) {
	key, e := base64.StdEncoding.DecodeString(secret)
	if e != nil || len(key) == 0 {
		return nil, fail(400, "invalid_arguments")
	}
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	return h.Sum(nil), nil
}
func GenerateAuthCode(secret string, unix int64) (string, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(unix/30))
	mac, e := guardMAC(secret, b)
	if e != nil {
		return "", e
	}
	off := mac[19] & 15
	n := binary.BigEndian.Uint32(mac[off:off+4]) & 0x7fffffff
	alphabet := "23456789BCDFGHJKMNPQRTVWXY"
	out := make([]byte, 5)
	for i := range out {
		out[i] = alphabet[n%uint32(len(alphabet))]
		n /= uint32(len(alphabet))
	}
	return string(out), nil
}
func GenerateConfirmationKey(secret, tag string, unix int64) (string, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(unix))
	t := []byte(tag)
	if len(t) > 32 {
		t = t[:32]
	}
	mac, e := guardMAC(secret, append(b, t...))
	if e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(mac), nil
}

var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func encryptPassword(password, modulus, exponent string) (string, error) {
	normalized := strings.TrimLeft(modulus, "0")
	if len(modulus) > 1024 || len(normalized) < 256 || len(exponent) > 8 || !hexPattern.MatchString(modulus) || !hexPattern.MatchString(exponent) {
		return "", fail(502, "invalid_rsa_key")
	}
	n, ok := new(big.Int).SetString(normalized, 16)
	exp, e := strconv.ParseUint(exponent, 16, 32)
	if !ok || e != nil || n.Bit(0) != 1 || exp < 3 || exp&1 == 0 {
		return "", fail(502, "invalid_rsa_key")
	}
	if len([]byte(password)) > (len(normalized)+1)/2-11 {
		return "", fail(400, "password_too_long")
	}
	out, e := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{N: n, E: int(exp)}, []byte(password))
	if e != nil {
		return "", fail(502, "invalid_rsa_key")
	}
	return base64.StdEncoding.EncodeToString(out), nil
}
