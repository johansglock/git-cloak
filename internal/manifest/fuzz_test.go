package manifest

import (
	"testing"

	"github.com/johans/git-cloak/internal/crypto"
)

// FuzzManifestDecrypt fuzzes the manifest blob parser/decryptor. It must never
// panic; any error is acceptable.
func FuzzManifestDecrypt(f *testing.F) {
	set, _ := crypto.NewDEK()
	dek, _ := set.CurrentKey()
	m := New(1)
	m.Refs["refs/heads/main"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if blob, err := m.Encrypt(dek, set.Current); err == nil {
		f.Add(blob)
	}
	f.Add([]byte("CLOAK1garbage"))
	f.Add([]byte{})

	lookup := func(gen uint32) ([]byte, error) { return set.Get(gen) }
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = PeekHeader(data)
		_, _ = Decrypt(data, lookup)
	})
}
