package store

import (
	"bytes"
	"crypto/rand"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/manifest"
)

// bareRemote creates a local bare git repo to stand in for the GitHub encrypted
// store during tests.
func bareRemote(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init", "--bare", "-b", "main", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	return dir
}

func TestStoreCreatePushClone(t *testing.T) {
	remote := bareRemote(t)
	dekSet, _ := crypto.NewDEK()
	dek, _ := dekSet.CurrentKey()

	// --- writer side: clone empty, init layout, push ---
	wdir := filepath.Join(t.TempDir(), "store")
	s, err := OpenOrClone(wdir, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteConfig(DefaultConfig([]string{"recip1"})); err != nil {
		t.Fatal(err)
	}

	// Multi-chunk pack: small split forces >=2 chunk files.
	chunkSize := 1024
	splitBytes := int64(crypto.HeaderLen + 2*(chunkSize+crypto.TagLen)) // budget = 2 inner chunks
	packPlain := make([]byte, 5000)
	if _, err := rand.Read(packPlain); err != nil {
		t.Fatal(err)
	}
	var packID [crypto.SaltIDLen]byte
	rand.Read(packID[:])
	chunks, err := s.WritePack(packID, dek, dekSet.Current, bytes.NewReader(packPlain), splitBytes, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if chunks < 2 {
		t.Fatalf("expected >=2 chunks, got %d", chunks)
	}

	m := manifest.New(1)
	m.Head = "refs/heads/main"
	m.Refs["refs/heads/main"] = "0123456789012345678901234567890123456789"
	m.Packs = append(m.Packs, manifest.PackRecord{
		PackID:        hexID(packID),
		DEKGeneration: dekSet.Current,
		Chunks:        chunks,
		ObjectCount:   42,
	})
	mblob, err := m.Encrypt(dek, dekSet.Current)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFile(ManifestFile, mblob); err != nil {
		t.Fatal(err)
	}
	committed, err := s.Commit("cloak store update")
	if err != nil {
		t.Fatal(err)
	}
	if !committed {
		t.Fatal("expected a commit")
	}
	if err := s.Push(false); err != nil {
		t.Fatal(err)
	}

	// --- reader side: fresh clone, decrypt, verify identity ---
	rdir := filepath.Join(t.TempDir(), "store2")
	s2, err := OpenOrClone(rdir, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Fetch(); err != nil {
		t.Fatal(err)
	}
	mblob2, err := s2.ReadFile(ManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := manifest.Decrypt(mblob2, func(gen uint32) ([]byte, error) { return dekSet.Get(gen) })
	if err != nil {
		t.Fatal(err)
	}
	if m2.Generation != 1 || m2.Refs["refs/heads/main"] != m.Refs["refs/heads/main"] {
		t.Fatalf("manifest mismatch: %+v", m2)
	}
	if len(m2.Packs) != 1 || m2.Packs[0].Chunks != chunks {
		t.Fatalf("pack record mismatch: %+v", m2.Packs)
	}

	var got bytes.Buffer
	if err := s2.ReadPack(m2.Packs[0].PackID, m2.Packs[0].Chunks, m2.Packs[0].DEKGeneration, dek, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), packPlain) {
		t.Fatalf("pack round-trip mismatch: got %d bytes want %d", got.Len(), len(packPlain))
	}

	// Tampering with a chunk must be detected.
	bad, _ := s2.ReadFile(PackChunkPath(m2.Packs[0].PackID, 0))
	bad[len(bad)-1] ^= 0x01
	if err := s2.WriteFile(PackChunkPath(m2.Packs[0].PackID, 0), bad); err != nil {
		t.Fatal(err)
	}
	if err := s2.VerifyPack(m2.Packs[0].PackID, m2.Packs[0].Chunks, m2.Packs[0].DEKGeneration, dek); err == nil {
		t.Fatal("expected tamper detection on corrupted chunk")
	}
}

func hexID(id [crypto.SaltIDLen]byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(id)*2)
	for i, b := range id {
		out[i*2] = hexd[b>>4]
		out[i*2+1] = hexd[b&0x0f]
	}
	return string(out)
}
