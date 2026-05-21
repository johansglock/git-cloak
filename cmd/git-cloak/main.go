// Command git-cloak is the porcelain CLI for managing an encrypted git remote on
// GitHub: identity, recipients, key rotation, status, verification, and gc. The
// transport itself is handled by the git-remote-cloak helper; wiring up a remote
// is plain git (`git remote add origin cloak::<github-url>`).
package main

import (
	"fmt"
	"os"
)

const usage = `git-cloak — an encrypted git remote for GitHub

Usage: git cloak <command> [args]

Setup:
  init [--insecure-plaintext-identity]   Create this machine's identity key
  id                                     Print this machine's public identity key
  create <cloak-url>                     Initialize the encrypted store in an empty GitHub repo

Recipients & keys:
  add-recipient <pubkey | @file>         Grant a collaborator access (wrap the repo key)
  list-recipients                        List recipients of the encrypted store
  remove-recipient <id>                  Revoke a recipient's wrap (then rotate-key)
  rotate-key                             New DEK generation; future pushes use it
  export-key <file> | import-key <file>  Move the repo key between machines out-of-band

Inspect & maintain:
  status                                 Show store url, generation, sizes, recipients
  verify                                 Verify all AEAD tags + manifest consistency (read-only)
  gc                                     Consolidate packs into one and shrink the store
  unlock | lock                          Cache / drop the repo key for the session

After setup, plain git just works:
  git remote add origin cloak::<github-url>
  git push -u origin main
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "id":
		err = cmdID(args)
	case "create":
		err = cmdCreate(args)
	case "add-recipient":
		err = cmdAddRecipient(args)
	case "list-recipients":
		err = cmdListRecipients(args)
	case "remove-recipient":
		err = cmdRemoveRecipient(args)
	case "rotate-key":
		err = cmdRotateKey(args)
	case "status":
		err = cmdStatus(args)
	case "verify":
		err = cmdVerify(args)
	case "gc":
		err = cmdGC(args)
	case "unlock":
		err = cmdUnlock(args)
	case "lock":
		err = cmdLock(args)
	case "export-key":
		err = cmdExportKey(args)
	case "import-key":
		err = cmdImportKey(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "git-cloak: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-cloak: %v\n", err)
		os.Exit(1)
	}
}
