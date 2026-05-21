package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "regenerate golden test vectors")

// fixedHeader builds a fully-deterministic pack header for vector generation.
func fixedHeader(chunkSize uint32) BlobHeader {
	var h BlobHeader
	h.Version = FormatVersion
	h.Cipher = CipherXChaCha
	h.ChunkSize = chunkSize
	h.DEKGen = 1
	for i := range h.SaltID {
		h.SaltID[i] = byte(i)
	}
	h.ChunkIndex = 0
	for i := range h.NoncePrefix {
		h.NoncePrefix[i] = byte(0xA0 + i)
	}
	return h
}

func sealToBytes(t *testing.T, key, plaintext []byte, h BlobHeader) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := SealStream(&buf, bytes.NewReader(plaintext), key, h); err != nil {
		t.Fatalf("SealStream: %v", err)
	}
	return buf.Bytes()
}

func openToBytes(key, blob []byte) ([]byte, error) {
	r := bytes.NewReader(blob)
	h, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := OpenStream(&out, r, key, h); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func TestStreamRoundTrip(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, KeyLen)
	sizes := []int{0, 1, 100, DefaultChunkSize - 1, DefaultChunkSize, DefaultChunkSize + 1, 3*DefaultChunkSize + 7}
	for _, n := range sizes {
		plaintext := make([]byte, n)
		for i := range plaintext {
			plaintext[i] = byte(i * 7)
		}
		h := fixedHeader(DefaultChunkSize)
		key, err := DeriveKey(dek, PackSalt(h.SaltID, h.ChunkIndex), InfoPack)
		if err != nil {
			t.Fatal(err)
		}
		blob := sealToBytes(t, key, plaintext, h)
		got, err := openToBytes(key, blob)
		if err != nil {
			t.Fatalf("size %d: open: %v", n, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round-trip mismatch", n)
		}
	}
}

// goldenVector is a checked-in known-answer test (S §9.6).
type goldenVector struct {
	Name         string `json:"name"`
	DEKHex       string `json:"dek_hex"`
	ChunkSize    uint32 `json:"chunk_size"`
	PlaintextHex string `json:"plaintext_hex"`
	BlobHex      string `json:"blob_hex"`
}

func goldenPath() string { return filepath.Join("testdata", "vectors.json") }

func buildGoldenVectors(t *testing.T) []goldenVector {
	t.Helper()
	dek := bytes.Repeat([]byte{0x42}, KeyLen)
	cases := []struct {
		name      string
		chunkSize uint32
		plaintext []byte
	}{
		{"empty", 16, nil},
		{"single-byte", 16, []byte{0x01}},
		{"one-full-chunk", 16, bytes.Repeat([]byte{0xAB}, 16)},
		{"multi-chunk", 16, []byte("the quick brown fox jumps over the lazy dog!!")},
	}
	var out []goldenVector
	for _, c := range cases {
		h := fixedHeader(c.chunkSize)
		key, err := DeriveKey(dek, PackSalt(h.SaltID, h.ChunkIndex), InfoPack)
		if err != nil {
			t.Fatal(err)
		}
		blob := sealToBytes(t, key, c.plaintext, h)
		out = append(out, goldenVector{
			Name:         c.name,
			DEKHex:       hex.EncodeToString(dek),
			ChunkSize:    c.chunkSize,
			PlaintextHex: hex.EncodeToString(c.plaintext),
			BlobHex:      hex.EncodeToString(blob),
		})
	}
	return out
}

func TestGoldenVectors(t *testing.T) {
	vectors := buildGoldenVectors(t)
	if *update {
		data, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath(), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d golden vectors", len(vectors))
		return
	}

	raw, err := os.ReadFile(goldenPath())
	if err != nil {
		t.Fatalf("read golden vectors (run: go test -run TestGoldenVectors -update): %v", err)
	}
	var want []goldenVector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(vectors) {
		t.Fatalf("vector count drift: golden %d, generated %d", len(want), len(vectors))
	}
	for i := range want {
		if want[i] != vectors[i] {
			t.Errorf("vector %q drifted from golden file; ciphertext is not reproducible", want[i].Name)
		}
		// Positive: each golden blob decrypts to its plaintext.
		dek, _ := hex.DecodeString(want[i].DEKHex)
		var saltID [SaltIDLen]byte
		for j := range saltID {
			saltID[j] = byte(j)
		}
		key, err := DeriveKey(dek, PackSalt(saltID, 0), InfoPack)
		if err != nil {
			t.Fatal(err)
		}
		blob, _ := hex.DecodeString(want[i].BlobHex)
		got, err := openToBytes(key, blob)
		if err != nil {
			t.Fatalf("vector %q: decrypt failed: %v", want[i].Name, err)
		}
		wantPT, _ := hex.DecodeString(want[i].PlaintextHex)
		if !bytes.Equal(got, wantPT) {
			t.Errorf("vector %q: plaintext mismatch", want[i].Name)
		}
	}
}

// TestNegativeVectors covers S §9.6: flipped byte, dropped final chunk, swapped
// chunks, and wrong key must all fail decryption.
func TestNegativeVectors(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, KeyLen)
	h := fixedHeader(16)
	key, err := DeriveKey(dek, PackSalt(h.SaltID, h.ChunkIndex), InfoPack)
	if err != nil {
		t.Fatal(err)
	}
	// 3 inner chunks of 16 bytes each.
	plaintext := bytes.Repeat([]byte{0xCC}, 16*2+5)
	blob := sealToBytes(t, key, plaintext, h)

	t.Run("flipped-body-byte", func(t *testing.T) {
		bad := append([]byte(nil), blob...)
		bad[len(bad)-1] ^= 0x01
		if _, err := openToBytes(key, bad); err == nil {
			t.Fatal("expected failure on flipped body byte")
		}
	})

	t.Run("flipped-header-byte", func(t *testing.T) {
		bad := append([]byte(nil), blob...)
		bad[HeaderLen-1] ^= 0x01 // flip last nonce-prefix byte
		if _, err := openToBytes(key, bad); err == nil {
			t.Fatal("expected failure on flipped header byte")
		}
	})

	t.Run("dropped-final-chunk", func(t *testing.T) {
		// Remove the last (final-flagged) inner chunk. The previous chunk then
		// gets decrypted as final and must fail.
		encChunk := 16 + TagLen
		bad := blob[:len(blob)-(5+TagLen)] // last chunk is 5 bytes plaintext + tag
		_ = encChunk
		if _, err := openToBytes(key, bad); err == nil {
			t.Fatal("expected failure on dropped final chunk")
		}
	})

	t.Run("swapped-chunks", func(t *testing.T) {
		encChunk := 16 + TagLen
		body := append([]byte(nil), blob[HeaderLen:]...)
		// swap chunk 0 and chunk 1 (both full)
		c0 := append([]byte(nil), body[0:encChunk]...)
		c1 := append([]byte(nil), body[encChunk:2*encChunk]...)
		copy(body[0:encChunk], c1)
		copy(body[encChunk:2*encChunk], c0)
		bad := append(append([]byte(nil), blob[:HeaderLen]...), body...)
		if _, err := openToBytes(key, bad); err == nil {
			t.Fatal("expected failure on swapped chunks")
		}
	})

	t.Run("wrong-key", func(t *testing.T) {
		wrong := bytes.Repeat([]byte{0x43}, KeyLen)
		wkey, _ := DeriveKey(wrong, PackSalt(h.SaltID, h.ChunkIndex), InfoPack)
		if _, err := openToBytes(wkey, blob); err == nil {
			t.Fatal("expected failure with wrong key")
		}
	})

	t.Run("truncated-header", func(t *testing.T) {
		if _, err := openToBytes(key, blob[:HeaderLen-1]); err == nil {
			t.Fatal("expected failure on truncated header")
		}
	})
}

// TestNonceUniqueness asserts that distinct (salt, info) pairs yield distinct
// subkeys (S3), so identical nonce prefixes cannot cause a real nonce collision.
func TestNonceUniqueness(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, KeyLen)
	var sid [SaltIDLen]byte
	k0, _ := DeriveKey(dek, PackSalt(sid, 0), InfoPack)
	k1, _ := DeriveKey(dek, PackSalt(sid, 1), InfoPack)
	km, _ := DeriveKey(dek, ManifestSalt(1), InfoManifest)
	if bytes.Equal(k0, k1) || bytes.Equal(k0, km) || bytes.Equal(k1, km) {
		t.Fatal("subkeys collided across salt/info domains")
	}
}
