package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// PublicKeyPrefix prefixes the shareable string form of an identity public key.
const PublicKeyPrefix = "cloak1"

// PublicKeyString renders a public key as a shareable token: "cloak1" + hex.
func PublicKeyString(pub [32]byte) string {
	return PublicKeyPrefix + hex.EncodeToString(pub[:])
}

// ParsePublicKey parses a token produced by PublicKeyString.
func ParsePublicKey(s string) ([32]byte, error) {
	var pub [32]byte
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, PublicKeyPrefix) {
		return pub, fmt.Errorf("crypto: public key must start with %q", PublicKeyPrefix)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(s, PublicKeyPrefix))
	if err != nil {
		return pub, fmt.Errorf("crypto: invalid public key hex: %w", err)
	}
	if len(raw) != 32 {
		return pub, fmt.Errorf("crypto: public key must be 32 bytes, got %d", len(raw))
	}
	copy(pub[:], raw)
	return pub, nil
}

// Argon2id parameters for identity-file protection. Conservative interactive
// defaults; tunable only by bumping the format if needed.
const (
	idMagic        = "CLOAKID1"
	argonTime      = 3
	argonMemoryKiB = 64 * 1024 // 64 MiB
	argonThreads   = 4
	argonSaltLen   = 16

	// Bounds on the KDF parameters accepted from a file header. We always write
	// the fixed values above; these caps simply prevent a hostile/corrupt file
	// from forcing a giant allocation or an unbounded work factor (DoS).
	argonMaxTime    = 16
	argonMinMemKiB  = 8 * 1024   // 8 MiB
	argonMaxMemKiB  = 256 * 1024 // 256 MiB
	argonMaxThreads = 16
)

// ErrIdentityDecrypt is returned when an encrypted identity file cannot be
// decrypted (wrong passphrase or tampered file).
var ErrIdentityDecrypt = errors.New("crypto: cannot decrypt identity (wrong passphrase or corrupt file)")

// sealArgon2 seals plaintext under a passphrase with Argon2id key derivation and
// XChaCha20-Poly1305. magic must be 8 bytes. Format:
// magic(8) || time(4) || memKiB(4) || threads(1) || salt(16) || nonce(24) || ct.
func sealArgon2(magic string, plaintext, passphrase []byte) ([]byte, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemoryKiB, argonThreads, KeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, len(magic)+9)
	hdr = append(hdr, magic...)
	hdr = binary.BigEndian.AppendUint32(hdr, argonTime)
	hdr = binary.BigEndian.AppendUint32(hdr, argonMemoryKiB)
	hdr = append(hdr, argonThreads)

	out := make([]byte, 0, len(hdr)+argonSaltLen+len(nonce)+len(plaintext)+TagLen)
	out = append(out, hdr...)
	out = append(out, salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, hdr), nil
}

// openArgon2 reverses sealArgon2, verifying the magic. A wrong passphrase, wrong
// magic, or any tamper yields fail (returns nil, false).
func openArgon2(magic string, blob, passphrase []byte) ([]byte, bool) {
	hdrLen := len(magic) + 9
	if len(blob) < hdrLen+argonSaltLen+chacha20poly1305.NonceSizeX+TagLen {
		return nil, false
	}
	if string(blob[:len(magic)]) != magic {
		return nil, false
	}
	off := len(magic)
	t := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	mem := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	threads := blob[off]
	off++
	// The KDF parameters come from the (untrusted) file header. Reject anything
	// outside a sane band before calling argon2.IDKey, so a malicious or corrupt
	// file cannot trigger an enormous allocation or an unbounded work factor.
	if t < 1 || t > argonMaxTime || mem < argonMinMemKiB || mem > argonMaxMemKiB || threads < 1 || threads > argonMaxThreads {
		return nil, false
	}
	salt := blob[off : off+argonSaltLen]
	off += argonSaltLen
	nonce := blob[off : off+chacha20poly1305.NonceSizeX]
	off += chacha20poly1305.NonceSizeX
	ct := blob[off:]

	key := argon2.IDKey(passphrase, salt, t, mem, threads, KeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, false
	}
	plain, err := aead.Open(nil, nonce, ct, blob[:hdrLen])
	if err != nil {
		return nil, false
	}
	return plain, true
}

// EncryptIdentity seals an identity keypair under a passphrase. The plaintext is
// the 32-byte private key followed by the public key; both are bound by the AEAD
// tag (the public half is recomputable but stored for convenience).
func EncryptIdentity(id Identity, passphrase []byte) ([]byte, error) {
	plain := make([]byte, 64)
	copy(plain[:32], id.Private[:])
	copy(plain[32:], id.Public[:])
	return sealArgon2(idMagic, plain, passphrase)
}

// DecryptIdentity recovers an identity from a blob produced by EncryptIdentity.
func DecryptIdentity(blob, passphrase []byte) (Identity, error) {
	var id Identity
	plain, ok := openArgon2(idMagic, blob, passphrase)
	if !ok || len(plain) != 64 {
		return id, ErrIdentityDecrypt
	}
	copy(id.Private[:], plain[:32])
	copy(id.Public[:], plain[32:])
	return id, nil
}

// ConstantTimeEqual reports whether a and b are equal without leaking timing.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

const pwMagic = "CLOAKPW1"

// ErrPassphraseDecrypt is returned when a passphrase-sealed blob cannot be
// opened (wrong passphrase or tampered).
var ErrPassphraseDecrypt = errors.New("crypto: cannot decrypt (wrong passphrase or corrupt data)")

// SealPassphrase encrypts arbitrary plaintext under a passphrase. Used by
// `git cloak export-key` to protect an exported repo key for out-of-band
// transport, so the key is never written unprotected.
func SealPassphrase(plaintext, passphrase []byte) ([]byte, error) {
	return sealArgon2(pwMagic, plaintext, passphrase)
}

// OpenPassphrase reverses SealPassphrase.
func OpenPassphrase(blob, passphrase []byte) ([]byte, error) {
	plain, ok := openArgon2(pwMagic, blob, passphrase)
	if !ok {
		return nil, ErrPassphraseDecrypt
	}
	return plain, nil
}
