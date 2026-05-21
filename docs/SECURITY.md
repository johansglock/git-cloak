# git-cloak — security & cryptographic specification

This document is the authoritative description of git-cloak's threat model,
cryptography, and known limitations. If anything here disagrees with the code,
the code is a bug.

> **No external audit.** This is a reference implementation of a sound design.
> The constructions are standard (XChaCha20-Poly1305 STREAM, X25519 sealed
> boxes, HKDF, Argon2id) but the integration has not been independently
> reviewed.

---

## 1. Threat model

### Assets
Repository contents, full history, commit messages, author identities,
filenames, directory structure, branch/tag names.

### Adversary: GitHub itself, or anyone with read access to the encrypted repo
Can read, list, retain, and serve the encrypted repo; can attempt to tamper
with, truncate, replay, force-push, or roll back its history.

**Must not learn:** any plaintext, filenames, commit messages, ref names, or the
real history graph.

**May learn (accepted residual leakage):** total size of the encrypted repo,
the size of each push, the number of commits/packs, and the timing/frequency of
pushes. Manifest padding (opt-in) blunts the ref/pack-count signal but is not a
guarantee.

**Must not be able to, undetected:** modify, truncate, reorder chunks within a
pack, swap packs between repos, drop a pack, or roll the store back to an older
state.

### Adversary: a former collaborator
Held a valid identity + repo key in the past and cloned the repo.

- *Accepted:* they can still read everything they cloned. Unavoidable for
  distributed history.
- *Mitigated:* after `rotate-key` + recipient removal, they cannot read future
  pushes.

### Out of scope
Compromise of a current collaborator's machine or identity key; a malicious
`git` binary; side channels from push timing.

---

## 2. Cryptographic primitives

| Purpose | Primitive | Library |
|---|---|---|
| Stream AEAD (packs, manifest) | XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` (`NewX`) |
| Key wrapping to recipients | X25519 sealed box | `golang.org/x/crypto/nacl/box` (`SealAnonymous`/`OpenAnonymous`) |
| Subkey derivation | HKDF-SHA-256 | `golang.org/x/crypto/hkdf` |
| Identity & exported-key at rest | XChaCha20-Poly1305 + Argon2id | `golang.org/x/crypto/argon2`, `chacha20poly1305` |
| Randomness | CSPRNG | `crypto/rand` |

All pure Go, no cgo.

## 3. Keys

- **Identity key** — per user, per machine: an X25519 keypair. The public half
  is shared with repo owners to be added as a recipient; the private half lives
  in the local keystore.
- **DEK (data-encryption key)** — per repository: a random 32-byte symmetric
  key. Encrypts the manifest and all packs.
- **DEK generations** — `rotate-key` creates a new DEK; old generations are
  retained so old packs stay readable. Each pack records the generation it used.

## 4. STREAM chunked AEAD (packs and manifest)

Every encrypted blob (each pack chunk file is its own blob; the manifest is one
blob) is a STREAM construction (as used by `age`):

1. **Subkey:** `K = HKDF-SHA256(secret = DEK, salt, info)`.
   - Packs: `salt = packid (16) || chunk_index (4, BE)`, `info =
     "git-cloak/v1/pack"`.
   - Manifest: `salt = generation (8, BE)`, `info = "git-cloak/v1/manifest"`.
   - Distinct (salt, info) ⇒ independent subkeys, so a per-blob nonce can never
     collide across blobs (requirement S3).
2. **Header** (55 bytes, cleartext, authenticated): `magic "CLOAK1" (6) ||
   version (1) || cipher (1) || chunk_size (4, BE) || dek_generation (4, BE) ||
   salt_id (16) || chunk_index (4, BE) || nonce_prefix (19)`. For the manifest,
   `salt_id` holds the generation counter (left-packed); for packs it holds the
   random pack id.
3. **Plaintext** is split into fixed `chunk_size` (default 64 KiB) chunks.
4. **Nonce** for chunk *i* (24 bytes): `nonce_prefix (19) || uint32_be(i) (4) ||
   final_flag (1)`, where `final_flag = 0x01` on the last chunk, else `0x00`.
5. **AAD** for chunk *i*: `header_bytes (55) || uint32_be(i) (4) || final_flag
   (1)`. (This binds the entire header — superset of the spec's required
   fields.)
6. **Blob** = `header || Seal(chunk_0) || … || Seal(chunk_n)`.

This satisfies:

- **S1** (authenticated): every chunk carries a Poly1305 tag; any bit flip in
  the header or body fails decryption.
- **S2** (anti-truncation / anti-reorder): a truncated blob is missing its
  `final_flag = 0x01` chunk and the now-last chunk fails its AAD/nonce check; a
  reordered chunk fails because *i* is bound into the nonce and AAD. Decryption
  fails **closed** — no plaintext is emitted past a bad chunk.
- **S3** (no nonce collision): per-blob subkeys are domain-separated by salt.

### Pack chunking and GitHub's limits
A git packfile is encrypted into one or more numbered chunk files
`packs/<packid>.NNN.pack.enc`, each sized so its ciphertext stays under
`pack_split_bytes` (default ~90 MiB), comfortably below GitHub's 100 MB
per-file hard limit. Dropping a whole chunk file is detected because the
authenticated manifest records the exact chunk count per pack. `packid` is a
random 128-bit value (not a content hash) so GitHub cannot detect identical
packs across repos.

## 5. Key wrapping

For each recipient with X25519 public key `R`:

```
keys/<id>.wrap = box.SealAnonymous(plaintext = all_DEK_generations, peer = R)
```

`id = hex(SHA-256(R)[:16])`. To unlock, a recipient runs `box.OpenAnonymous`
with their identity private key. Adding a recipient writes one new `.wrap`;
removing one deletes their `.wrap` (and you should then `rotate-key`).

`cloak.json` records each recipient's public key (a `cloak1…` token); public
keys and the ids derived from them are safe to expose and are required to re-wrap
the DEK on `add-recipient` and `rotate-key`.

## 6. Rollback / force-push protection (S4)

The manifest carries a monotonically increasing `generation` counter, bumped on
every push. The client persists the highest generation it has accepted in
`.git/cloak/state.json`. On fetch, after decrypting the manifest, if
`manifest.generation < last_generation` the client **aborts loudly** — a
possible malicious force-push, rollback, or corruption. The first clone
establishes the trust baseline (TOFU). Pointing at `git cloak verify` is the
recommended next step.

## 7. Identity & exported keys at rest

- **Identity file** (`identity.enc`): `magic "CLOAKID1" || argon2_time (4) ||
  argon2_mem_kib (4) || argon2_threads (1) || salt (16) || nonce (24) || ct`.
  Key = Argon2id(passphrase, salt, t=3, m=64 MiB, p=4) → XChaCha20-Poly1305 over
  the 64-byte (private||public) identity, with the header as AAD.
- **Exported repo key** (`export-key`): same scheme with magic `CLOAKPW1` over
  the serialized DEK set, so a repo key transferred out-of-band is never written
  unprotected.
- **Plaintext identity** (`identity.json`): only with
  `--insecure-plaintext-identity`; 0600 perms; warned about loudly.

No secret material is ever placed on a command line (argv), in a log line, or in
an error string (requirement S5). Decryption errors are intentionally generic.

## 8. Test vectors

`internal/crypto/testdata/vectors.json` holds checked-in known-answer vectors
(fixed DEK + fixed plaintext + fixed nonce prefix → fixed ciphertext).
`go test ./internal/crypto` verifies both that those blobs reproduce exactly
(format stability) and that negative cases — flipped header/body byte, dropped
final chunk, swapped chunks, wrong key, truncated header — all fail. Fuzz
targets (`FuzzOpenStream`, `FuzzParseDEKSet`, `FuzzOpenPassphrase`,
`FuzzManifestDecrypt`) assert the parsers never panic and always fail closed.

## 9. Limitations (read this)

- **No revocation of distributed history.** Anyone who held a key and cloned can
  read what they cloned. `rotate-key` only protects future pushes.
- **Metadata side channels.** Push size/timing/frequency and pack counts leak
  (§1). Padding is opt-in mitigation, not a guarantee.
- **Multi-writer is best-effort**, riding on git's non-fast-forward rejection.
  Optimized for a single writer across multiple machines.
- **No external audit.**

## 10. Reporting a vulnerability

Please report security issues privately to the maintainer rather than opening a
public issue. Provide a description, affected version/commit, and a reproduction
if possible.
