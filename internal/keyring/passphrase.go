package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Prompter obtains a passphrase. confirm requests double-entry (for new
// passphrases). Implementations must never echo or log the secret.
type Prompter func(prompt string, confirm bool) ([]byte, error)

// ErrNoPassphrase indicates a passphrase was needed but none could be obtained
// (no CLOAK_PASSPHRASE and no terminal).
var ErrNoPassphrase = errors.New("keyring: passphrase required but stdin is not a terminal; set CLOAK_PASSPHRASE")

// EnvOrTerminal is the default Prompter. It uses the CLOAK_PASSPHRASE environment
// variable if set, otherwise reads from the controlling terminal without echo.
func EnvOrTerminal(prompt string, confirm bool) ([]byte, error) {
	if p, ok := os.LookupEnv("CLOAK_PASSPHRASE"); ok {
		return []byte(p), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, ErrNoPassphrase
	}
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		again, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pass, again) {
			return nil, errors.New("keyring: passphrases did not match")
		}
	}
	return pass, nil
}
