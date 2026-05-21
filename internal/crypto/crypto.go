// Package crypto implements git-cloak's authenticated-encryption core: a STREAM
// chunked AEAD over XChaCha20-Poly1305, HKDF subkey derivation, X25519 sealed-box
// key wrapping, and Argon2id-protected identity files. It performs no I/O beyond
// the io.Reader/io.Writer passed to the streaming functions and contains no
// git-cloak domain logic, so it can be exercised entirely with fixed test vectors.
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// Magic prefixes every STREAM blob header.
	Magic = "CLOAK1"
	// FormatVersion is the on-disk blob format version.
	FormatVersion = 1
	// CipherXChaCha identifies XChaCha20-Poly1305 in the header.
	CipherXChaCha = 1

	// DefaultChunkSize is the STREAM inner-chunk plaintext size (64 KiB).
	DefaultChunkSize = 65536

	// KeyLen is the symmetric key size (32 bytes).
	KeyLen = chacha20poly1305.KeySize
	// TagLen is the Poly1305 tag size added to every inner chunk.
	TagLen = chacha20poly1305.Overhead
	// NoncePrefixLen is the random per-blob nonce prefix length. With the 4-byte
	// chunk counter and 1-byte final flag this yields a 24-byte XChaCha20 nonce.
	NoncePrefixLen = 19
	// SaltIDLen is the size of the header salt-id field (a pack id, or a manifest
	// generation left-packed into 16 bytes).
	SaltIDLen = 16

	// HeaderLen is the fixed serialized blob-header length.
	HeaderLen = 6 /*magic*/ + 1 /*version*/ + 1 /*cipher*/ + 4 /*chunkSize*/ +
		4 /*dekGen*/ + SaltIDLen + 4 /*chunkIndex*/ + NoncePrefixLen // = 55

	// Info strings domain-separate HKDF subkeys (S3).
	InfoPack     = "git-cloak/v1/pack"
	InfoManifest = "git-cloak/v1/manifest"

	maxChunkSize = 1 << 24 // 16 MiB sanity cap on the declared chunk size
)

// Errors returned by the streaming decryptor. They are intentionally generic so
// callers can fail closed without revealing which check failed.
var (
	ErrBadMagic    = errors.New("crypto: bad blob magic")
	ErrShortHeader = errors.New("crypto: truncated blob header")
	ErrAuthFailed  = errors.New("crypto: authentication failed (tampered, reordered, or wrong key)")
	ErrTruncated   = errors.New("crypto: blob truncated (missing final chunk)")
)

// BlobHeader is the cleartext, AEAD-authenticated header at the start of every
// STREAM blob. Every field is bound into the AAD of every chunk, so any
// modification fails decryption.
type BlobHeader struct {
	Version     uint8
	Cipher      uint8
	ChunkSize   uint32
	DEKGen      uint32
	SaltID      [SaltIDLen]byte
	ChunkIndex  uint32
	NoncePrefix [NoncePrefixLen]byte
}

// Marshal serializes the header to its fixed-length wire form.
func (h BlobHeader) Marshal() []byte {
	b := make([]byte, HeaderLen)
	copy(b[0:6], Magic)
	b[6] = h.Version
	b[7] = h.Cipher
	binary.BigEndian.PutUint32(b[8:12], h.ChunkSize)
	binary.BigEndian.PutUint32(b[12:16], h.DEKGen)
	copy(b[16:32], h.SaltID[:])
	binary.BigEndian.PutUint32(b[32:36], h.ChunkIndex)
	copy(b[36:55], h.NoncePrefix[:])
	return b
}

// ReadHeader reads and validates a blob header from r.
func ReadHeader(r io.Reader) (BlobHeader, error) {
	var h BlobHeader
	b := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, b); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return h, ErrShortHeader
		}
		return h, err
	}
	if string(b[0:6]) != Magic {
		return h, ErrBadMagic
	}
	h.Version = b[6]
	h.Cipher = b[7]
	h.ChunkSize = binary.BigEndian.Uint32(b[8:12])
	h.DEKGen = binary.BigEndian.Uint32(b[12:16])
	copy(h.SaltID[:], b[16:32])
	h.ChunkIndex = binary.BigEndian.Uint32(b[32:36])
	copy(h.NoncePrefix[:], b[36:55])
	if h.Version != FormatVersion {
		return h, fmt.Errorf("crypto: unsupported blob version %d", h.Version)
	}
	if h.Cipher != CipherXChaCha {
		return h, fmt.Errorf("crypto: unsupported cipher id %d", h.Cipher)
	}
	if h.ChunkSize == 0 || h.ChunkSize > maxChunkSize {
		return h, fmt.Errorf("crypto: invalid chunk size %d", h.ChunkSize)
	}
	return h, nil
}

// DeriveKey derives a 32-byte subkey from a DEK using HKDF-SHA256. salt and info
// domain-separate the result (S3): distinct (salt, info) pairs yield independent
// keys, so per-blob nonces can never collide across blobs.
func DeriveKey(dek, salt []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, dek, salt, []byte(info))
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// PackSalt builds the HKDF salt for a pack chunk file: packid || chunkIndex.
func PackSalt(saltID [SaltIDLen]byte, chunkIndex uint32) []byte {
	b := make([]byte, SaltIDLen+4)
	copy(b[:SaltIDLen], saltID[:])
	binary.BigEndian.PutUint32(b[SaltIDLen:], chunkIndex)
	return b
}

// ManifestSalt builds the HKDF salt for the manifest: the generation counter.
func ManifestSalt(generation uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, generation)
	return b
}

// GenerationSaltID packs a manifest generation into a 16-byte SaltID field.
func GenerationSaltID(generation uint64) [SaltIDLen]byte {
	var s [SaltIDLen]byte
	binary.BigEndian.PutUint64(s[:8], generation)
	return s
}

// RecipientID is the public, safe-to-expose identifier for a recipient: the
// hex-encoded first 16 bytes of SHA-256 over the X25519 public key.
func RecipientID(pub [32]byte) string {
	sum := sha256.Sum256(pub[:])
	return hex.EncodeToString(sum[:16])
}
