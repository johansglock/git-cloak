package main

import (
	"fmt"
	"os"

	"github.com/johans/git-cloak/internal/keyring"
)

func cmdRotateKey(args []string) error {
	s, err := openSession()
	if err != nil {
		return err
	}
	if err := s.RotateKey(); err != nil {
		return err
	}
	fmt.Println("Rotated repo key. Future pushes use the new DEK generation.")
	fmt.Println("Note: anyone who already cloned can still read prior history (this cannot be revoked).")
	return nil
}

func cmdGC(args []string) error {
	s, err := openSession()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Consolidating packs and rewriting store history (this force-pushes)…")
	if err := s.GC(); err != nil {
		return err
	}
	fmt.Println("Done. The store was repacked into a single pack and force-pushed.")
	return nil
}

func cmdExportKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: git cloak export-key <file>")
	}
	s, err := openSession()
	if err != nil {
		return err
	}
	pass, err := prompt("Set a passphrase to protect the exported key: ", true)
	if err != nil {
		return err
	}
	blob, err := s.ExportKey(pass)
	if err != nil {
		return err
	}
	if err := os.WriteFile(args[0], blob, 0o600); err != nil {
		return err
	}
	fmt.Printf("Exported repo key to %s (passphrase-protected). Transfer it out-of-band.\n", args[0])
	return nil
}

func cmdImportKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: git cloak import-key <file>")
	}
	r, err := openRepo()
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	pass, err := prompt("Enter the passphrase for the imported key: ", false)
	if err != nil {
		return err
	}
	if err := r.ImportKey(blob, pass, keyring.EnvOrTerminal); err != nil {
		return err
	}
	fmt.Println("Imported repo key and granted this machine access. You can now push/pull.")
	return nil
}
