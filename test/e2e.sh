#!/usr/bin/env bash
# End-to-end test of git-cloak against a local bare repo standing in for GitHub.
# Builds the binaries, then exercises the full lifecycle:
#   init, create, push, clone, object-for-object identity, plaintext-leak check,
#   incremental push, multi-recipient cross-machine clone, status, verify,
#   export-key/import-key, rollback detection, rotate-key + remove-recipient
#   (revocation), gc consolidation, and the encrypted-identity passphrase path.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/.e2e/bin"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Build fresh binaries.
mkdir -p "$BIN"
( cd "$ROOT" && go build -o "$BIN/git-cloak" ./cmd/git-cloak && go build -o "$BIN/git-remote-cloak" ./cmd/git-remote-cloak )

export PATH="$BIN:$PATH"
export GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=tester GIT_AUTHOR_EMAIL=tester@example.com
export GIT_COMMITTER_NAME=tester GIT_COMMITTER_EMAIL=tester@example.com

note() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

ENC="$WORK/enc.git"
git init -q --bare -b main "$ENC"
URL="cloak::file://$ENC"

count_packs() { local d="$WORK/scan$$"; rm -rf "$d"; git clone -q "$ENC" "$d"; ls "$d/packs" 2>/dev/null | wc -l | tr -d ' '; rm -rf "$d"; }

# ---------------------------------------------------------------- machine A
export GIT_CLOAK_HOME="$WORK/idA"
note "machine A: init identity"
git-cloak init --insecure-plaintext-identity >/dev/null
PUBA="$(git-cloak id)"

SRC="$WORK/src"; mkdir -p "$SRC"; git -C "$SRC" init -q -b main
echo "hello world" > "$SRC/README.md"
mkdir -p "$SRC/dir"; echo "secret contents" > "$SRC/dir/file.txt"
git -C "$SRC" add -A; git -C "$SRC" commit -q -m "initial commit"
echo "more" >> "$SRC/README.md"; git -C "$SRC" commit -qam "second commit"
git -C "$SRC" tag v1
HEAD_A="$(git -C "$SRC" rev-parse HEAD)"

note "create + push"
( cd "$SRC" && git-cloak create "$URL" >/dev/null )
git -C "$SRC" remote add origin "$URL"
git -C "$SRC" push -q -u origin main
git -C "$SRC" push -q origin v1
( cd "$SRC" && git-cloak status )
( cd "$SRC" && git-cloak verify )

note "clone back + object identity"
CLONE="$WORK/clone"; git clone -q "$URL" "$CLONE"
[ "$HEAD_A" = "$(git -C "$CLONE" rev-parse HEAD)" ] || fail "HEAD mismatch"
git -C "$CLONE" fsck --full >/dev/null 2>&1 || fail "git fsck failed"
diff -r "$SRC/dir" "$CLONE/dir" >/dev/null || fail "file contents differ"
git -C "$CLONE" rev-parse v1 >/dev/null 2>&1 || fail "tag v1 not cloned"
echo "OK HEAD=$HEAD_A"

note "leak check"
SCAN="$WORK/scan"; git clone -q "$ENC" "$SCAN"
grep -rqI "secret contents" "$SCAN" 2>/dev/null && fail "plaintext leaked!" || true
grep -rqI "second commit" "$SCAN" 2>/dev/null && fail "commit message leaked!" || true
echo "no plaintext or commit messages in encrypted store OK"
rm -rf "$SCAN"

note "incremental push adds only a small pack"
B4=$(count_packs)
echo "tiny change" >> "$SRC/README.md"; git -C "$SRC" commit -qam "third commit"
git -C "$SRC" push -q origin main
A4=$(count_packs)
echo "pack chunks: $B4 -> $A4"
[ "$A4" -gt "$B4" ] || fail "no incremental pack added"

# ---------------------------------------------------------------- machine B
note "machine B: add as recipient, clone with its own identity"
export GIT_CLOAK_HOME="$WORK/idB"; git-cloak init --insecure-plaintext-identity >/dev/null
PUBB="$(git-cloak id)"
export GIT_CLOAK_HOME="$WORK/idA"
( cd "$SRC" && git-cloak add-recipient "$PUBB" )
export GIT_CLOAK_HOME="$WORK/idB"
CLONEB="$WORK/cloneB"; git clone -q "$URL" "$CLONEB"
[ "$(git -C "$CLONEB" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse HEAD)" ] || fail "B HEAD mismatch"
git -C "$CLONEB" fsck --full >/dev/null 2>&1 || fail "B fsck failed"
echo "cross-machine multi-recipient clone OK"

# ---------------------------------------------------------------- export/import
note "export-key on A, import-key on machine C"
export GIT_CLOAK_HOME="$WORK/idA"
KEYFILE="$WORK/repo.key"
( cd "$SRC" && CLOAK_PASSPHRASE="transfer-pass" git-cloak export-key "$KEYFILE" )
export GIT_CLOAK_HOME="$WORK/idC"; git-cloak init --insecure-plaintext-identity >/dev/null
# C is not a recipient yet; bootstrap access by importing the key, then pull.
CLONEC="$WORK/cloneC"; mkdir -p "$CLONEC"
git -C "$CLONEC" init -q -b main
git -C "$CLONEC" remote add origin "$URL"
( cd "$CLONEC" && CLOAK_PASSPHRASE="transfer-pass" git-cloak import-key "$KEYFILE" )
git -C "$CLONEC" pull -q origin main
[ "$(git -C "$CLONEC" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse HEAD)" ] || fail "C HEAD mismatch after import-key"
echo "export/import-key OK"

# ---------------------------------------------------------------- rollback
note "rollback detection"
export GIT_CLOAK_HOME="$WORK/idA"
ORIG="$(git -C "$ENC" rev-parse main)"
( cd "$CLONE" && git fetch -q origin )   # bring clone's high-water mark up to date
ROOT_COMMIT="$(git -C "$ENC" rev-list --max-parents=0 main | head -1)"
git -C "$ENC" update-ref refs/heads/main "$ROOT_COMMIT"
if ( cd "$CLONE" && git fetch -q origin 2>/tmp/cloak_rb.$$ ); then fail "rollback NOT detected"; fi
grep -qi "rollback" /tmp/cloak_rb.$$ && echo "rollback correctly detected" || { cat /tmp/cloak_rb.$$; fail "no rollback message"; }
git -C "$ENC" update-ref refs/heads/main "$ORIG"   # restore store for further tests
rm -f /tmp/cloak_rb.$$

# ---------------------------------------------------------------- rotate + revoke
note "rotate-key + remove-recipient (revocation)"
# B's recipient id-hash, read from B's own identity (init reprints it).
BIDH="$(GIT_CLOAK_HOME="$WORK/idB" git-cloak init --insecure-plaintext-identity 2>/dev/null | awk '/Your id/{print $NF}')"
export GIT_CLOAK_HOME="$WORK/idA"
( cd "$SRC" && git-cloak remove-recipient "$BIDH" )
( cd "$SRC" && git-cloak rotate-key )
echo "newgen change" >> "$SRC/README.md"; git -C "$SRC" commit -qam "post-rotation commit"
git -C "$SRC" push -q origin main
( cd "$SRC" && git-cloak verify )   # A still verifies (has all DEK gens)
# B can no longer access a fresh clone.
export GIT_CLOAK_HOME="$WORK/idB"
if git clone -q "$URL" "$WORK/cloneB2" 2>/tmp/cloak_rev.$$; then fail "removed recipient B could still clone!"; fi
echo "removed recipient B can no longer clone OK"
rm -f /tmp/cloak_rev.$$
export GIT_CLOAK_HOME="$WORK/idA"
# A can still clone fresh (gets pre- and post-rotation history).
git clone -q "$URL" "$WORK/cloneA2"
[ "$(git -C "$WORK/cloneA2" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse HEAD)" ] || fail "A re-clone HEAD mismatch"
echo "A still reads pre+post-rotation history OK"

# ---------------------------------------------------------------- gc
note "gc consolidation"
PKB=$(count_packs)
( cd "$SRC" && git-cloak gc )
PKA=$(count_packs)
echo "pack chunks: $PKB -> $PKA"
[ "$PKA" -le "$PKB" ] || fail "gc did not reduce/keep pack count"
( cd "$SRC" && git-cloak verify )
git clone -q "$URL" "$WORK/cloneGC"
[ "$(git -C "$WORK/cloneGC" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse HEAD)" ] || fail "post-gc clone HEAD mismatch"
git -C "$WORK/cloneGC" fsck --full >/dev/null 2>&1 || fail "post-gc fsck failed"
echo "gc OK, store still verifies and clones"

# ---------------------------------------------------------------- encrypted identity
note "encrypted-identity passphrase path"
export GIT_CLOAK_HOME="$WORK/idE"
CLOAK_PASSPHRASE="hunter2" "$BIN/git-cloak" init >/dev/null
PUBE="$(CLOAK_PASSPHRASE="hunter2" "$BIN/git-cloak" id)"
[ -f "$WORK/idE/identity.enc" ] || fail "encrypted identity file not created"
export GIT_CLOAK_HOME="$WORK/idA"
( cd "$SRC" && git-cloak add-recipient "$PUBE" )
export GIT_CLOAK_HOME="$WORK/idE"
CLOAK_PASSPHRASE="hunter2" git clone -q "$URL" "$WORK/cloneE"
[ "$(git -C "$WORK/cloneE" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse HEAD)" ] || fail "encrypted-identity clone HEAD mismatch"
echo "encrypted-identity clone OK"

note "ALL E2E CHECKS PASSED"
