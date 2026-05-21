package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// ErrUnwrap is returned when a wrap file cannot be opened with the given
// identity (wrong recipient, tampered, or corrupt).
var ErrUnwrap = errors.New("crypto: cannot unwrap repo key with this identity")

// Identity is a local X25519 keypair. The public half is shared with repo owners
// to be added as a recipient; the private half stays in the local keystore.
type Identity struct {
	Public  [32]byte
	Private [32]byte
}

// GenerateIdentity creates a new random X25519 identity keypair.
func GenerateIdentity() (Identity, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Public: *pub, Private: *priv}, nil
}

// ID returns this identity's public recipient id.
func (id Identity) ID() string { return RecipientID(id.Public) }

// WrapDEKSet seals a DEK set to a recipient's X25519 public key using a NaCl
// anonymous sealed box. The result is the contents of keys/<id>.wrap (S5: the
// plaintext DEK set never leaves memory unsealed).
func WrapDEKSet(set DEKSet, recipientPub [32]byte) ([]byte, error) {
	pub := recipientPub
	return box.SealAnonymous(nil, set.Marshal(), &pub, rand.Reader)
}

// UnwrapDEKSet opens a wrap file with a recipient's identity, recovering the DEK
// set. Fails closed if this identity is not the intended recipient.
func UnwrapDEKSet(wrapped []byte, id Identity) (DEKSet, error) {
	pub, priv := id.Public, id.Private
	pt, ok := box.OpenAnonymous(nil, wrapped, &pub, &priv)
	if !ok {
		return DEKSet{}, ErrUnwrap
	}
	return ParseDEKSet(pt)
}
