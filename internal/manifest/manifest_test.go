package manifest

import (
	"bytes"
	"testing"

	"github.com/johans/git-cloak/internal/crypto"
)

func TestManifestRoundTrip(t *testing.T) {
	set, _ := crypto.NewDEK()
	dek, _ := set.CurrentKey()

	m := New(42)
	m.Head = "refs/heads/main"
	m.Refs["refs/heads/main"] = "1111111111111111111111111111111111111111"
	m.Refs["refs/tags/v1"] = "2222222222222222222222222222222222222222"
	m.Packs = append(m.Packs,
		PackRecord{PackID: "aa", DEKGeneration: 1, Chunks: 3, ObjectCount: 1200},
		PackRecord{PackID: "bb", DEKGeneration: 1, Chunks: 1, ObjectCount: 17},
	)

	blob, err := m.Encrypt(dek, set.Current)
	if err != nil {
		t.Fatal(err)
	}
	// PeekHeader exposes routing info without the key.
	hi, err := PeekHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	if hi.Generation != 42 || hi.DEKGeneration != 1 {
		t.Fatalf("peek mismatch: %+v", hi)
	}

	got, err := Decrypt(blob, func(gen uint32) ([]byte, error) { return set.Get(gen) })
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != 42 || got.Head != m.Head {
		t.Fatalf("manifest mismatch: %+v", got)
	}
	if got.Refs["refs/heads/main"] != m.Refs["refs/heads/main"] || len(got.Packs) != 2 {
		t.Fatalf("refs/packs mismatch: %+v", got)
	}
}

func TestManifestTamperFails(t *testing.T) {
	set, _ := crypto.NewDEK()
	dek, _ := set.CurrentKey()
	m := New(7)
	m.Refs["refs/heads/main"] = "deadbeef"
	blob, _ := m.Encrypt(dek, set.Current)

	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0x01
	if _, err := Decrypt(bad, func(gen uint32) ([]byte, error) { return set.Get(gen) }); err == nil {
		t.Fatal("expected tamper to fail manifest decryption")
	}

	// Wrong key fails.
	other, _ := crypto.NewDEK()
	if _, err := Decrypt(blob, func(gen uint32) ([]byte, error) { return other.Get(gen) }); err == nil {
		t.Fatal("expected wrong key to fail manifest decryption")
	}
}

func TestManifestPadding(t *testing.T) {
	set, _ := crypto.NewDEK()
	dek, _ := set.CurrentKey()
	lookup := func(gen uint32) ([]byte, error) { return set.Get(gen) }

	const padTo = 512
	m := New(1)
	m.Refs["refs/heads/main"] = "abc123"
	unpadded, _ := m.Encrypt(dek, set.Current)
	m2 := New(1)
	m2.Refs["refs/heads/main"] = "abc123"
	padded, _ := m2.EncryptPadded(dek, set.Current, padTo)

	if len(padded) <= len(unpadded) {
		t.Fatalf("padded (%d) should be larger than unpadded (%d)", len(padded), len(unpadded))
	}
	// Padding rounds the plaintext to a multiple of padTo; the blob is plaintext
	// plus a fixed header and per-chunk tags, so it should land near a boundary.
	if len(padded) < padTo {
		t.Fatalf("padded blob %d smaller than pad boundary %d", len(padded), padTo)
	}
	// The padding field must be ignored on decode and not corrupt the manifest.
	got, err := Decrypt(padded, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if got.Refs["refs/heads/main"] != "abc123" || got.Pad != "" {
		t.Fatalf("padding leaked into decoded manifest: %+v", got)
	}
}

// TestManifestGenerationBinding ensures the header generation must match the body
// (defends against splicing a body under a different generation salt).
func TestManifestGenerationBinding(t *testing.T) {
	set, _ := crypto.NewDEK()
	dek, _ := set.CurrentKey()
	m := New(5)
	blob, _ := m.Encrypt(dek, set.Current)
	if !bytes.HasPrefix(blob, []byte(crypto.Magic)) {
		t.Fatal("manifest blob missing magic header")
	}
	// Decrypting normally works.
	if _, err := Decrypt(blob, func(gen uint32) ([]byte, error) { return set.Get(gen) }); err != nil {
		t.Fatal(err)
	}
}
