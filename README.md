# git-cloak

Push any git repository to **GitHub** in a form where GitHub — and anyone with
read access to the repo — learns essentially nothing: not file contents, not
filenames, not commit messages, not branch names, not history shape. Your
**local** repository stays a completely normal git repo: you run `git clone`,
`git push`, `git pull`, `git log` exactly as usual. Encryption and decryption
happen transparently inside a git *remote helper*.

The encrypted side lives on GitHub as an **ordinary private GitHub repo** whose
contents are nothing but opaque encrypted blobs. There is no new storage system
and no new credential to manage: git-cloak moves data using plain `git` over
whatever GitHub authentication you already use (SSH key, `gh`, or a credential
helper).

git-cloak is inspired by [`git-crypt`](https://github.com/AGWA/git-crypt) for
ergonomics but is a different tool: `git-crypt` encrypts selected *files* and
leaves history and metadata public; git-cloak encrypts the *entire repository*,
so GitHub sees only ciphertext.

> **Status:** reference implementation. Crypto is modern and authenticated, but
> this has not had an external audit. Read [`docs/SECURITY.md`](docs/SECURITY.md)
> before trusting it with anything irreplaceable.

---

## Install

Requires Go 1.23+ and `git` on your `PATH`. Pure Go, no cgo.

```sh
go install github.com/johans/git-cloak/cmd/git-cloak@latest
go install github.com/johans/git-cloak/cmd/git-remote-cloak@latest
```

Or from a checkout:

```sh
make install            # installs both binaries into $(go env GOPATH)/bin
```

Both binaries must be on your `PATH`. `git` discovers `git-remote-cloak`
automatically for any `cloak::` URL, and runs `git-cloak` when you type
`git cloak …`.

---

## Quick start

```sh
# one-time per machine: create your identity key
git cloak init

# create an empty PRIVATE repo on GitHub (one click, or `gh repo create`),
# then initialize the encrypted store inside it:
cd my-repo
git cloak create cloak::git@github.com:me/myrepo-enc.git

# wire up the remote and push — objects are encrypted, then pushed:
git remote add origin cloak::git@github.com:me/myrepo-enc.git
git push -u origin main

# on another machine that holds an authorized identity key:
git clone cloak::git@github.com:me/myrepo-enc.git
```

After setup, `git push` / `git pull` behave exactly like normal git. URLs work
over SSH or HTTPS — anything after `cloak::` is handed verbatim to plain `git`:

```
cloak::git@github.com:me/myrepo-enc.git        # SSH
cloak::https://github.com/me/myrepo-enc.git    # HTTPS
```

## Collaborating

Access is granted by X25519 public key — no passwords, no GPG.

```sh
# a collaborator runs this and sends you the line it prints:
git cloak id
#   cloak1a1b2c…

# you grant them access (re-wraps the repo key to their key, then pushes):
git cloak add-recipient cloak1a1b2c…
git cloak list-recipients
```

To revoke someone:

```sh
git cloak remove-recipient <id>   # deletes their wrapped key
git cloak rotate-key              # so they cannot read FUTURE pushes
```

Rotation limits *future* exposure only. Anyone who already cloned keeps what
they cloned — distributed history cannot be un-distributed (same as `git-crypt`).

## Maintenance

```sh
git cloak status     # url, generation, pack/chunk counts, store size, recipients
git cloak verify     # check every AEAD tag + manifest consistency (read-only)
git cloak gc         # consolidate packs into one and shrink the GitHub repo
```

---

## What GitHub *can* still see

git-cloak is **not** a metadata-perfect system. The encrypted GitHub repo is a
real git repo of binary blobs, and that necessarily reveals some side
information (accepted residual leakage):

- **Total size** of the encrypted repo, and the **size of each push**.
- The **number of commits/packs** and roughly how history grows over time.
- The **timing and frequency** of your pushes.

It does **not** reveal plaintext, filenames, commit messages, author identities,
ref/branch/tag names, or the real history graph.

Optional opt-in **manifest padding** (`git cloak create --pad N`) rounds the
encrypted manifest up to a size boundary to blunt the "how many refs/packs"
signal. Padding is a mitigation, not a guarantee, and is off by default to keep
the GitHub repo small. Use `git cloak gc` to keep total size down.

---

## How it works (in one breath)

The encrypted store is an ordinary GitHub repo containing a cleartext
`cloak.json` (no secrets), an encrypted `manifest.enc` (the source of truth for
refs), `packs/<id>.NNN.pack.enc` (encrypted git packfiles, chunked under
GitHub's 100 MB file limit), and `keys/<id>.wrap` (the repo key sealed to each
recipient). On push, the helper asks git for an incremental packfile of only the
new objects, encrypts it, and pushes the store; on fetch it decrypts the packs
and feeds them back to git. Because whole packfiles are encrypted, git's own
delta + zlib compression runs *before* encryption. See
[`docs/SECURITY.md`](docs/SECURITY.md) for the full cryptographic spec.

## Identity keys

Your identity private key is stored as a **keyfile** under
`~/.config/git-cloak/` (override with `GIT_CLOAK_HOME` or `XDG_CONFIG_HOME`):

- **Encrypted (default):** `identity.enc`, sealed with XChaCha20-Poly1305 under
  an Argon2id-derived passphrase. Set `CLOAK_PASSPHRASE` to avoid prompts in
  scripts and for the remote helper (which cannot prompt interactively).
- **Plaintext:** `identity.json`, only with `git cloak init
  --insecure-plaintext-identity`.

git-cloak deliberately ships **no OS-keychain backend**: a pure-Go (no cgo)
macOS Keychain integration cannot avoid exposing the secret on a process command
line, so keyfiles are used instead.

To move repo access to a new machine out-of-band:

```sh
git cloak export-key repo.key      # passphrase-protected
# …transfer repo.key securely…
git cloak import-key repo.key      # grants this machine access
```

---

## Limitations

- Not a partial/selective per-file encryption tool (that's `git-crypt`).
- Not metadata-perfect (see "What GitHub can still see").
- Cannot revoke already-distributed history; rotation limits future exposure.
- GitHub only — no pluggable storage backends.
- No Git LFS; large packs are split into `<100 MB` chunks.
- Multi-writer is best-effort and rides on git's normal non-fast-forward
  rejection; the common case is one person across multiple machines.

## Development

```sh
make test        # go test -race ./...  (+ vet, staticcheck if installed)
make e2e         # full lifecycle against a local bare repo
make fuzz        # short fuzz run of the blob/manifest parsers
```

## License

MIT — see [`LICENSE`](LICENSE).
