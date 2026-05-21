package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/johans/git-cloak/internal/cloak"
	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/keyring"
)

// prompt is the passphrase provider for all commands.
var prompt = keyring.EnvOrTerminal

// openRepo discovers the local repo and its cloak:: remote URL.
func openRepo() (*cloak.Repo, error) {
	gitDir, err := cloak.DiscoverGitDir()
	if err != nil {
		return nil, err
	}
	url, err := cloak.DiscoverURL(gitDir)
	if err != nil {
		return nil, err
	}
	return cloak.Open(gitDir, url), nil
}

func openSession() (*cloak.Session, error) {
	r, err := openRepo()
	if err != nil {
		return nil, err
	}
	return r.OpenSession(prompt)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	insecure := fs.Bool("insecure-plaintext-identity", false, "store the identity key UNENCRYPTED on disk")
	fs.Parse(args)

	if keyring.Exists() {
		id, err := keyring.Load(prompt)
		if err != nil {
			return err
		}
		fmt.Printf("Identity already exists.\nYour public key: %s\nYour id:         %s\n",
			crypto.PublicKeyString(id.Public), id.ID())
		return nil
	}
	backend := keyring.BackendEncrypted
	if *insecure {
		fmt.Fprintln(os.Stderr, "WARNING: storing identity private key UNENCRYPTED (--insecure-plaintext-identity)")
		backend = keyring.BackendPlaintext
	}
	id, err := keyring.GenerateAndSave(backend, prompt)
	if err != nil {
		return err
	}
	fmt.Printf("Created identity in %s\n", keyring.ConfigDir())
	fmt.Printf("Your public key: %s\n", crypto.PublicKeyString(id.Public))
	fmt.Printf("Your id:         %s\n", id.ID())
	fmt.Println("\nShare your public key with a repo owner so they can add you as a recipient.")
	return nil
}

func cmdID(args []string) error {
	id, err := keyring.Load(prompt)
	if err != nil {
		return err
	}
	fmt.Println(crypto.PublicKeyString(id.Public))
	return nil
}

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	pad := fs.Int("pad", 0, "round the encrypted manifest up to a multiple of N bytes (size obfuscation; 0=off)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: git cloak create [--pad N] <cloak-url>")
	}
	gitDir, err := cloak.DiscoverGitDir()
	if err != nil {
		return err
	}
	url := cloak.StripScheme(fs.Arg(0))
	r := cloak.Open(gitDir, url)
	if err := r.Create(prompt, *pad); err != nil {
		return err
	}
	fmt.Printf("Initialized encrypted store at %s\n", url)
	fmt.Printf("Now wire up the remote:\n  git remote add origin cloak::%s\n  git push -u origin <branch>\n", url)
	return nil
}

func cmdStatus(args []string) error {
	s, err := openSession()
	if err != nil {
		return err
	}
	st, err := s.Status()
	if err != nil {
		return err
	}
	fmt.Printf("Encrypted store:   %s\n", st.URL)
	fmt.Printf("Generation:        %d\n", st.Generation)
	fmt.Printf("Packs:             %d (%d chunk files, %d objects)\n", st.PackCount, st.ChunkCount, st.ObjectCount)
	fmt.Printf("Store size:        %s\n", humanBytes(st.StoreSizeBytes))
	fmt.Printf("Recipients:        %d\n", st.RecipientCount)
	fmt.Printf("DEK generations:   %d\n", st.DEKGenerations)
	fmt.Printf("HEAD:              %s\n", st.Head)
	if len(st.Refs) > 0 {
		fmt.Println("Refs:")
		refs := make([]string, 0, len(st.Refs))
		for r := range st.Refs {
			refs = append(refs, r)
		}
		sort.Strings(refs)
		for _, r := range refs {
			fmt.Printf("  %s %s\n", st.Refs[r][:min(12, len(st.Refs[r]))], r)
		}
	}
	return nil
}

func cmdVerify(args []string) error {
	s, err := openSession()
	if err != nil {
		return err
	}
	if err := s.Verify(); err != nil {
		return fmt.Errorf("VERIFICATION FAILED: %w", err)
	}
	fmt.Println("OK: manifest and all packs verified; no corruption detected.")
	return nil
}

func cmdListRecipients(args []string) error {
	s, err := openSession()
	if err != nil {
		return err
	}
	recips, err := s.ListRecipients()
	if err != nil {
		return err
	}
	for _, r := range recips {
		marker := ""
		if r.IsSelf {
			marker = " (this machine)"
		}
		if !r.HasWrap {
			marker += " [MISSING WRAP]"
		}
		fmt.Printf("%s%s\n", r.ID, marker)
	}
	return nil
}

func cmdAddRecipient(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: git cloak add-recipient <pubkey | @file>")
	}
	tok := args[0]
	if strings.HasPrefix(tok, "@") {
		data, err := os.ReadFile(strings.TrimPrefix(tok, "@"))
		if err != nil {
			return err
		}
		tok = strings.TrimSpace(string(data))
	}
	pub, err := crypto.ParsePublicKey(tok)
	if err != nil {
		return err
	}
	s, err := openSession()
	if err != nil {
		return err
	}
	id, err := s.AddRecipient(pub)
	if err != nil {
		return err
	}
	fmt.Printf("Added recipient %s\n", id)
	return nil
}

func cmdRemoveRecipient(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: git cloak remove-recipient <id>")
	}
	s, err := openSession()
	if err != nil {
		return err
	}
	if err := s.RemoveRecipient(args[0]); err != nil {
		return err
	}
	fmt.Printf("Removed recipient %s\n", args[0])
	fmt.Println("They can still read history they already cloned. To deny them FUTURE pushes, run:")
	fmt.Println("  git cloak rotate-key")
	return nil
}

func cmdUnlock(args []string) error {
	// With keyfile-only storage there is no cross-process secret cache. Unlock
	// simply verifies access is possible; export CLOAK_PASSPHRASE to avoid
	// repeated prompts within a shell session.
	if _, err := openSession(); err != nil {
		return err
	}
	fmt.Println("Access verified. To avoid repeated passphrase prompts, export CLOAK_PASSPHRASE in your shell.")
	return nil
}

func cmdLock(args []string) error {
	fmt.Println("Nothing to lock: git-cloak keeps no on-disk session key (keyfile-only).")
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
