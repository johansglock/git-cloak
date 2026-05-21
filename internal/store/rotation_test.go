package store

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/johans/git-cloak/internal/crypto"
)

// TestRotationRevocation is the precise M4 property: after a key rotation in
// which a recipient is NOT re-wrapped, that recipient can still decrypt
// pre-rotation packs (the generation they hold) but cannot decrypt post-rotation
// packs, while a retained recipient can decrypt both.
func TestRotationRevocation(t *testing.T) {
	remote := bareRemote(t)
	s, err := OpenOrClone(filepath.Join(t.TempDir(), "store"), remote)
	if err != nil {
		t.Fatal(err)
	}

	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	// Generation 1: both Alice and Bob are wrapped.
	deks, _ := crypto.NewDEK()
	dek1, _ := deks.Get(1)
	bobWrap, _ := crypto.WrapDEKSet(deks, bob.Public) // Bob frozen at gen 1

	p1Plain := make([]byte, 4096)
	rand.Read(p1Plain)
	var p1ID [crypto.SaltIDLen]byte
	rand.Read(p1ID[:])
	if _, err := s.WritePack(p1ID, dek1, 1, bytes.NewReader(p1Plain), DefaultPackSplitBytes, crypto.DefaultChunkSize); err != nil {
		t.Fatal(err)
	}

	// Rotate to generation 2; only Alice is re-wrapped (Bob is "removed").
	deks2, _ := deks.Rotate()
	dek2, _ := deks2.Get(2)
	aliceWrap, _ := crypto.WrapDEKSet(deks2, alice.Public)

	p2Plain := make([]byte, 4096)
	rand.Read(p2Plain)
	var p2ID [crypto.SaltIDLen]byte
	rand.Read(p2ID[:])
	if _, err := s.WritePack(p2ID, dek2, 2, bytes.NewReader(p2Plain), DefaultPackSplitBytes, crypto.DefaultChunkSize); err != nil {
		t.Fatal(err)
	}

	bobDEKs, err := crypto.UnwrapDEKSet(bobWrap, bob)
	if err != nil {
		t.Fatal(err)
	}
	aliceDEKs, err := crypto.UnwrapDEKSet(aliceWrap, alice)
	if err != nil {
		t.Fatal(err)
	}

	// Bob: gen-1 pack readable, gen-2 pack NOT.
	bk1, _ := bobDEKs.Get(1)
	if err := s.VerifyPack(hexID(p1ID), 1, 1, bk1); err != nil {
		t.Fatalf("Bob should still read pre-rotation pack: %v", err)
	}
	if _, err := bobDEKs.Get(2); err == nil {
		t.Fatal("Bob must NOT possess the gen-2 key")
	}

	// Alice: both readable.
	ak1, _ := aliceDEKs.Get(1)
	ak2, _ := aliceDEKs.Get(2)
	if err := s.VerifyPack(hexID(p1ID), 1, 1, ak1); err != nil {
		t.Fatalf("Alice should read gen-1 pack: %v", err)
	}
	if err := s.VerifyPack(hexID(p2ID), 1, 2, ak2); err != nil {
		t.Fatalf("Alice should read gen-2 pack: %v", err)
	}
}
