// Package manifest encodes, decodes, and authenticated-encrypts the git-cloak
// manifest: the encrypted source of truth for the real repository's refs and the
// list of packs that make up its history. The manifest is stored on GitHub as
// manifest.enc and carries a monotonically increasing generation counter that
// drives rollback protection (S4).
package manifest

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/johans/git-cloak/internal/crypto"
)

// randomFiller returns n base64 characters of cryptographically random filler.
func randomFiller(n int) (string, error) {
	raw := make([]byte, (n*3)/4+1)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := base64.RawStdEncoding.EncodeToString(raw)
	if len(s) > n {
		s = s[:n]
	}
	return s, nil
}

// Format is the manifest schema version.
const Format = 1

// PackRecord describes one encrypted pack in the store.
type PackRecord struct {
	PackID        string `json:"packid"`         // hex of the 128-bit random pack id
	DEKGeneration uint32 `json:"dek_generation"` // which DEK generation encrypted it
	Chunks        int    `json:"chunks"`         // number of *.NNN.pack.enc chunk files
	ObjectCount   int    `json:"object_count"`   // git objects in the pack (informational)
}

// Manifest is the decrypted manifest contents.
type Manifest struct {
	Format     int               `json:"format"`
	Generation uint64            `json:"generation"`
	Head       string            `json:"head"`
	Refs       map[string]string `json:"refs"`
	Packs      []PackRecord      `json:"packs"`
	// Pad is optional incompressible filler that rounds the encrypted manifest's
	// size up to a configured boundary, so the ciphertext size leaks less about
	// the number of refs/packs (opt-in, off by default — N2). Ignored on decode.
	Pad string `json:"_pad,omitempty"`
}

// New returns an empty manifest at the given generation.
func New(generation uint64) *Manifest {
	return &Manifest{
		Format:     Format,
		Generation: generation,
		Refs:       map[string]string{},
		Packs:      []PackRecord{},
	}
}

// PackIDBytes parses a hex pack id into its 16-byte form.
func PackIDBytes(hexID string) ([crypto.SaltIDLen]byte, error) {
	var id [crypto.SaltIDLen]byte
	b, err := hex.DecodeString(hexID)
	if err != nil {
		return id, err
	}
	if len(b) != crypto.SaltIDLen {
		return id, fmt.Errorf("manifest: pack id must be %d bytes, got %d", crypto.SaltIDLen, len(b))
	}
	copy(id[:], b)
	return id, nil
}

// Encrypt serializes and seals the manifest with the current DEK generation.
func (m *Manifest) Encrypt(dek []byte, dekGen uint32) ([]byte, error) {
	return m.EncryptPadded(dek, dekGen, 0)
}

// EncryptPadded is Encrypt with optional size-obfuscation padding: the plaintext
// is rounded up to a multiple of padTo bytes with incompressible filler before
// sealing. padTo <= 0 disables padding.
func (m *Manifest) EncryptPadded(dek []byte, dekGen uint32, padTo int) ([]byte, error) {
	if m.Format == 0 {
		m.Format = Format
	}
	m.Pad = ""
	if padTo > 0 {
		base, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		// Round the (post-pad) size up to a multiple of padTo. The pad field adds
		// roughly len(`,"_pad":""`)+k bytes; over-pad slightly then it is exact
		// enough for obfuscation.
		const fieldOverhead = 10
		target := ((len(base)+fieldOverhead)/padTo + 1) * padTo
		k := target - len(base) - fieldOverhead
		if k > 0 {
			filler, err := randomFiller(k)
			if err != nil {
				return nil, err
			}
			m.Pad = filler
		}
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	h, err := crypto.NewManifestHeader(m.Generation, dekGen, crypto.DefaultChunkSize)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKey(dek, crypto.ManifestSalt(m.Generation), crypto.InfoManifest)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := crypto.SealStream(&buf, bytes.NewReader(plain), key, h); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HeaderInfo is the cleartext routing info needed before a manifest can be
// decrypted: which DEK generation sealed it.
type HeaderInfo struct {
	DEKGeneration uint32
	Generation    uint64
}

// PeekHeader reads the manifest blob header without decrypting, so a caller can
// learn which DEK generation it needs.
func PeekHeader(blob []byte) (HeaderInfo, error) {
	h, err := crypto.ReadHeader(bytes.NewReader(blob))
	if err != nil {
		return HeaderInfo{}, err
	}
	return HeaderInfo{DEKGeneration: h.DEKGen, Generation: crypto.ManifestGenerationFromHeader(h)}, nil
}

// Decrypt opens a manifest blob. lookup maps a DEK generation to its key.
func Decrypt(blob []byte, lookup func(gen uint32) ([]byte, error)) (*Manifest, error) {
	r := bytes.NewReader(blob)
	h, err := crypto.ReadHeader(r)
	if err != nil {
		return nil, err
	}
	gen := crypto.ManifestGenerationFromHeader(h)
	dek, err := lookup(h.DEKGen)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKey(dek, crypto.ManifestSalt(gen), crypto.InfoManifest)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := crypto.OpenStream(&out, r, key, h); err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		return nil, fmt.Errorf("manifest: corrupt plaintext: %w", err)
	}
	if m.Generation != gen {
		return nil, fmt.Errorf("manifest: header generation %d does not match body %d", gen, m.Generation)
	}
	if m.Refs == nil {
		m.Refs = map[string]string{}
	}
	m.Pad = "" // drop obfuscation filler; never surface it to callers
	return &m, nil
}
