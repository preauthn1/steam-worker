package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type vault struct {
	aead cipher.AEAD
	aad  []byte
}

func newVault(key, account string) (*vault, error) {
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("AES-256 key required")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &vault{a, []byte("steam-worker:v1:" + account)}, nil
}
func (v *vault) seal(value any) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, plain, v.aad)), nil
}
func (v *vault) open(value string, out any) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) < 29 {
		return errors.New("invalid envelope")
	}
	plain, err := v.aead.Open(nil, raw[:12], raw[12:], v.aad)
	if err != nil {
		return errors.New("invalid envelope")
	}
	return json.Unmarshal(plain, out)
}
