package crypto

import (
	"bytes"
	"testing"
)

// FuzzOpenStream fuzzes the STREAM blob parser/decryptor. It must never panic and
// must fail closed on any malformed, truncated, or tampered input.
func FuzzOpenStream(f *testing.F) {
	dek := bytes.Repeat([]byte{0x42}, KeyLen)
	h := fixedHeader(64)
	key, _ := DeriveKey(dek, PackSalt(h.SaltID, h.ChunkIndex), InfoPack)

	// Seed with a few valid blobs of varied sizes.
	for _, n := range []int{0, 1, 64, 200} {
		var buf bytes.Buffer
		pt := bytes.Repeat([]byte{0xCD}, n)
		_ = SealStream(&buf, bytes.NewReader(pt), key, h)
		f.Add(buf.Bytes())
	}
	f.Add([]byte("CLOAK1 not a real blob"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, blob []byte) {
		r := bytes.NewReader(blob)
		hdr, err := ReadHeader(r)
		if err != nil {
			return // rejected at the header; fine
		}
		var out bytes.Buffer
		// Use the fixed key; a real attacker doesn't have it, but this still
		// exercises the body parser. Any error is acceptable; a panic is not.
		_ = OpenStream(&out, r, key, hdr)
	})
}

// FuzzParseDEKSet fuzzes the wrapped-key-set parser.
func FuzzParseDEKSet(f *testing.F) {
	set, _ := NewDEK()
	set, _ = set.Rotate()
	f.Add(set.Marshal())
	f.Add([]byte{1, 0, 0, 0, 1, 0, 0, 0, 1})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseDEKSet(data) // must not panic
	})
}

// FuzzOpenPassphrase fuzzes the passphrase-sealed blob parser.
func FuzzOpenPassphrase(f *testing.F) {
	sealed, _ := SealPassphrase([]byte("hello"), []byte("pw"))
	f.Add(sealed)
	f.Add([]byte("CLOAKPW1short"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = OpenPassphrase(data, []byte("pw")) // must not panic
	})
}
