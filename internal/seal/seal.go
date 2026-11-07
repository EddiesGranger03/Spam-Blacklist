// Package seal protects blacklist data at rest.
//
//   - Seal/Open: AES-256-GCM, so a stolen database dump does not reveal values.
//   - Blind: HMAC-SHA256 with a secret pepper, so rows can still be matched by
//     equality (the checker only ever does equality lookups) without anyone
//     being able to brute-force phone numbers from the stored index.
//
// Both keys are derived with HKDF from separate secrets (DATA_KEY, DATA_PEPPER),
// so leaking one does not expose the other.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const minSecretLen = 32

// Column labels bind a ciphertext to the column it belongs to (used as AAD),
// so an attacker with write access cannot swap note_enc into value_enc.
const (
	AADValue  = "value"
	AADNote   = "note"
	AADSource = "source"
)

type Sealer struct {
	aead    cipher.AEAD
	pepper  []byte
	version int16
}

// New derives the encryption key and blind-index key from two separate secrets.
// version is stored next to every ciphertext to support key rotation.
func New(dataKey, pepper string, version int16) (*Sealer, error) {
	if len(dataKey) < minSecretLen || len(pepper) < minSecretLen {
		return nil, fmt.Errorf("DATA_KEY and DATA_PEPPER must each be at least %d characters", minSecretLen)
	}

	if dataKey == pepper {
		return nil, errors.New("DATA_KEY and DATA_PEPPER must be different secrets")
	}

	encKey, err := derive(dataKey, "vsf-data-encryption-v1")
	if err != nil {
		return nil, err
	}

	blindKey, err := derive(pepper, "vsf-blind-index-v1")
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Sealer{aead: aead, pepper: blindKey, version: version}, nil
}

func derive(secret, info string) ([]byte, error) {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, []byte(info)), out); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Sealer) Version() int16 { return s.version }

// Seal returns nonce || ciphertext. A fresh random nonce is used every call.
func (s *Sealer) Seal(plaintext, aad string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return s.aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad)), nil
}

func (s *Sealer) Open(blob []byte, aad string) (string, error) {
	n := s.aead.NonceSize()
	if len(blob) < n+s.aead.Overhead() {
		return "", errors.New("ciphertext too short")
	}

	pt, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return "", errors.New("decryption failed")
	}

	return string(pt), nil
}

// Blind returns the keyed lookup index for one (type, match type, value).
// Length-prefixed parts keep the encoding unambiguous.
func (s *Sealer) Blind(typ, matchType, value string) []byte {
	m := hmac.New(sha256.New, s.pepper)

	for _, p := range []string{typ, matchType, value} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		m.Write(n[:])
		m.Write([]byte(p))
	}

	return m.Sum(nil)
}

// Hash64 folds a blind index into the 64-bit value used for partitioning and
// the Bloom filter. Unlike xxhash of the plain value it cannot be brute-forced
// without the pepper.
func Hash64(blind []byte) int64 {
	return int64(binary.BigEndian.Uint64(blind[:8]))
}

// Mask keeps just enough of a value to recognise it (3 leading and 2 trailing
// characters) and hides the rest. Short values keep only their first character.
func Mask(v string) string {
	r := []rune(v)

	if len(r) <= 6 {
		if len(r) == 0 {
			return ""
		}

		return string(r[:1]) + "***"
	}

	return string(r[:3]) + "***" + string(r[len(r)-2:])
}

// Hasher adapts the Sealer to normalize.SetHasher.
func (s *Sealer) Hasher() func(typ, matchType, value string) (int64, []byte) {
	return func(typ, matchType, value string) (int64, []byte) {
		b := s.Blind(typ, matchType, value)
		return Hash64(b), b
	}
}
