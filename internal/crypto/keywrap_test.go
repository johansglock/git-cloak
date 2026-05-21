package crypto

import (
	"encoding/binary"
	"testing"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	set, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	set, err = set.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if set.Current != 2 || len(set.Keys) != 2 {
		t.Fatalf("unexpected set after rotate: current=%d keys=%d", set.Current, len(set.Keys))
	}

	alice, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapDEKSet(set, alice.Public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDEKSet(wrapped, alice)
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != set.Current || len(got.Keys) != len(set.Keys) {
		t.Fatal("unwrapped set differs")
	}
	for i := range set.Keys {
		if got.Keys[i].Generation != set.Keys[i].Generation || got.Keys[i].Key != set.Keys[i].Key {
			t.Fatalf("dek generation %d mismatch", set.Keys[i].Generation)
		}
	}
}

func TestUnwrapWrongIdentityFails(t *testing.T) {
	set, _ := NewDEK()
	alice, _ := GenerateIdentity()
	mallory, _ := GenerateIdentity()
	wrapped, _ := WrapDEKSet(set, alice.Public)
	if _, err := UnwrapDEKSet(wrapped, mallory); err == nil {
		t.Fatal("expected unwrap to fail for non-recipient")
	}
}

func TestPublicKeyStringRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	s := PublicKeyString(id.Public)
	got, err := ParsePublicKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != id.Public {
		t.Fatal("public key round-trip mismatch")
	}
	if _, err := ParsePublicKey("nope"); err == nil {
		t.Fatal("expected parse error for bad prefix")
	}
}

// TestOpenPassphraseRejectsHugeKDFParams guards against a malicious or corrupt
// keyfile forcing an enormous Argon2 allocation: the parameters come from the
// untrusted header and must be bounded before argon2.IDKey runs (regression for
// a fuzzer-discovered OOM).
func TestOpenPassphraseRejectsHugeKDFParams(t *testing.T) {
	const nonceLen = 24
	blob := make([]byte, len("CLOAKPW1")+9+argonSaltLen+nonceLen+TagLen)
	copy(blob, "CLOAKPW1")
	binary.BigEndian.PutUint32(blob[8:12], 1)           // time: fine
	binary.BigEndian.PutUint32(blob[12:16], 0xFFFFFFFF) // memory: absurd
	blob[16] = 1                                        // threads: fine
	if _, err := OpenPassphrase(blob, []byte("x")); err == nil {
		t.Fatal("expected rejection of absurd argon2 memory parameter")
	}
}

func TestIdentityFileRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	pass := []byte("correct horse battery staple")
	blob, err := EncryptIdentity(id, pass)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptIdentity(blob, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got.Private != id.Private || got.Public != id.Public {
		t.Fatal("identity round-trip mismatch")
	}
	if _, err := DecryptIdentity(blob, []byte("wrong")); err == nil {
		t.Fatal("expected decrypt failure with wrong passphrase")
	}
	// tamper
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0x01
	if _, err := DecryptIdentity(bad, pass); err == nil {
		t.Fatal("expected decrypt failure on tampered identity file")
	}
}
