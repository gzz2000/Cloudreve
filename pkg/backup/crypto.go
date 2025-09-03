package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// parseKey accepts hex-encoded key and returns raw bytes.
// Only hex is allowed to avoid ambiguity with base64.
func parseKey(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty encryption key")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encryption key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (hex-encoded 64 chars)")
	}
	return b, nil
}

// deriveIV derives a 16-byte IV using HMAC-SHA256(key, label) truncated to 16 bytes.
func deriveIV(key []byte, label []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(label)
	full := h.Sum(nil)
	iv := make([]byte, 16)
	copy(iv, full[:16])
	return iv, nil
}

// newCTRReader returns a reader that yields AES-CTR encrypted stream of r using key and iv.
func newCTRReader(r io.Reader, key []byte, iv []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	return &cipher.StreamReader{S: stream, R: r}, nil
}
