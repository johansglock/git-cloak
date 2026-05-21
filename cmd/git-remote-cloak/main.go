// Command git-remote-cloak is the git remote helper for cloak:: URLs. Git invokes
// it automatically for any remote whose URL begins with cloak::. It speaks the
// git remote-helper line protocol on stdin/stdout (gitremote-helpers(7)): all
// protocol output goes to stdout, all diagnostics to stderr.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/johans/git-cloak/internal/cloak"
	"github.com/johans/git-cloak/internal/keyring"
	"github.com/johans/git-cloak/internal/manifest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-cloak: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// git invokes: git-remote-cloak <remote> <url>. The url is the part after
	// cloak::; older gits may pass it via the remote arg only.
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(os.Stderr, "git-remote-cloak is a git remote helper invoked automatically by git for\n"+
			"cloak:: URLs. You do not run it directly. Manage encrypted remotes with\n"+
			"`git cloak …` and `git remote add origin cloak::<github-url>`.")
		return nil
	}
	var addr string
	switch len(args) {
	case 0:
		return fmt.Errorf("usage: git-remote-cloak <remote> <url>")
	case 1:
		addr = args[0]
	default:
		addr = args[1]
	}
	url := cloak.StripScheme(addr)

	gitDir, err := cloak.DiscoverGitDir()
	if err != nil {
		return err
	}
	h := &helper{
		repo: cloak.Open(gitDir, url),
		in:   bufio.NewReader(os.Stdin),
		out:  bufio.NewWriter(os.Stdout),
	}
	return h.serve()
}

type helper struct {
	repo    *cloak.Repo
	in      *bufio.Reader
	out     *bufio.Writer
	session *cloak.Session
}

func (h *helper) serve() error {
	for {
		line, err := h.in.ReadString('\n')
		if err == io.EOF {
			if strings.TrimSpace(line) == "" {
				return nil
			}
		} else if err != nil {
			return err
		}
		cmd := strings.TrimRight(line, "\n")
		switch {
		case cmd == "capabilities":
			h.send("fetch")
			h.send("push")
			h.send("option")
			h.send("")
		case cmd == "list" || cmd == "list for-push":
			if err := h.list(); err != nil {
				return err
			}
		case strings.HasPrefix(cmd, "option "):
			h.option(strings.TrimPrefix(cmd, "option "))
		case strings.HasPrefix(cmd, "fetch "):
			if err := h.fetch(cmd); err != nil {
				return err
			}
		case strings.HasPrefix(cmd, "push "):
			if err := h.push(cmd); err != nil {
				return err
			}
		case cmd == "":
			// Stray blank line outside a batch: ignore.
		default:
			return fmt.Errorf("unsupported command %q", cmd)
		}
		if err == io.EOF {
			return nil
		}
	}
}

// send writes one protocol line to stdout and flushes.
func (h *helper) send(s string) {
	fmt.Fprintln(h.out, s)
	h.out.Flush()
}

func (h *helper) option(rest string) {
	// We accept (and ignore) verbosity/progress; everything else is unsupported.
	name := rest
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		name = rest[:i]
	}
	switch name {
	case "verbosity", "progress", "cloning", "check-connectivity", "force", "atomic", "followtags":
		h.send("ok")
	default:
		h.send("unsupported")
	}
}

func (h *helper) ensureSession() (*cloak.Session, error) {
	if h.session != nil {
		return h.session, nil
	}
	s, err := h.repo.OpenSession(keyring.EnvOrTerminal)
	if err != nil {
		return nil, err
	}
	h.session = s
	return s, nil
}

func (h *helper) list() error {
	s, err := h.ensureSession()
	if err != nil {
		return err
	}
	m, err := s.ReadManifest()
	if err != nil {
		return err
	}
	writeRefs(h.out, m)
	h.out.Flush()
	return nil
}

func writeRefs(w io.Writer, m *manifest.Manifest) {
	for ref, sha := range m.Refs {
		fmt.Fprintf(w, "%s %s\n", sha, ref)
	}
	if m.Head != "" {
		if _, ok := m.Refs[m.Head]; ok {
			fmt.Fprintf(w, "@%s HEAD\n", m.Head)
		}
	}
	fmt.Fprintln(w) // terminating blank line
}

func (h *helper) fetch(first string) error {
	// Collect the batch of fetch lines until a blank line.
	_ = first // we import all needed packs regardless of the specific objects
	for {
		line, err := h.in.ReadString('\n')
		l := strings.TrimRight(line, "\n")
		if l == "" {
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	s, err := h.ensureSession()
	if err != nil {
		return err
	}
	if _, err := s.FetchAll(); err != nil {
		return err
	}
	fmt.Fprintln(h.out) // batch complete
	h.out.Flush()
	return nil
}

func (h *helper) push(first string) error {
	updates := []cloak.RefUpdate{}
	parse := func(spec string) {
		spec = strings.TrimPrefix(spec, "push ")
		force := false
		if strings.HasPrefix(spec, "+") {
			force = true
			spec = spec[1:]
		}
		parts := strings.SplitN(spec, ":", 2)
		u := cloak.RefUpdate{Src: parts[0], Force: force}
		if len(parts) == 2 {
			u.Dst = parts[1]
		}
		updates = append(updates, u)
	}
	parse(first)
	for {
		line, err := h.in.ReadString('\n')
		l := strings.TrimRight(line, "\n")
		if l == "" {
			break
		}
		if strings.HasPrefix(l, "push ") {
			parse(l)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	s, serr := h.ensureSession()
	if serr != nil {
		// Report the error against every ref so git surfaces it.
		for _, u := range updates {
			fmt.Fprintf(h.out, "error %s %s\n", u.Dst, sanitize(serr.Error()))
		}
		fmt.Fprintln(h.out)
		h.out.Flush()
		return nil
	}
	perr := s.Push(updates)
	for _, u := range updates {
		if perr == nil {
			fmt.Fprintf(h.out, "ok %s\n", u.Dst)
		} else {
			fmt.Fprintf(h.out, "error %s %s\n", u.Dst, sanitize(perr.Error()))
		}
	}
	fmt.Fprintln(h.out)
	h.out.Flush()
	if perr != nil {
		fmt.Fprintf(os.Stderr, "git-remote-cloak: push failed: %v\n", perr)
	}
	return nil
}

// sanitize collapses a multi-line error into a single protocol-safe token line.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
