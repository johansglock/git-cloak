package cloak

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/johans/git-cloak/internal/crypto"
	"github.com/johans/git-cloak/internal/manifest"
	"github.com/johans/git-cloak/internal/store"
)

// headPrefix is the ref namespace for branches.
const headPrefix = "refs/heads/"

// RefUpdate is one ref the caller wants to push. An empty Src means delete Dst.
type RefUpdate struct {
	Src   string
	Dst   string
	Force bool
}

const maxPushRetries = 5

// Push encrypts the new objects implied by updates, writes them and an updated
// manifest into the store, and pushes the store to GitHub. On a non-fast-forward
// rejection it re-syncs and retries against the new tip (§8), recomputing the
// incremental pack each attempt so it sends only what is still missing.
func (s *Session) Push(updates []RefUpdate) error {
	type resolvedRef struct {
		dst    string
		sha    string
		delete bool
	}
	var refs []resolvedRef
	for _, u := range updates {
		if u.Src == "" {
			refs = append(refs, resolvedRef{dst: u.Dst, delete: true})
			continue
		}
		sha, err := s.repo.git.revParse(u.Src)
		if err != nil {
			return fmt.Errorf("cannot resolve %q: %w", u.Src, err)
		}
		refs = append(refs, resolvedRef{dst: u.Dst, sha: sha})
	}

	var lastErr error
	for attempt := 0; attempt < maxPushRetries; attempt++ {
		if attempt > 0 {
			if err := s.Store.Fetch(); err != nil {
				return err
			}
			// A concurrent writer may have changed sizing/padding in cloak.json.
			cfg, err := s.Store.ReadConfig()
			if err != nil {
				return err
			}
			s.Config = cfg
		}
		m, err := s.ReadManifest()
		if err != nil {
			return err
		}

		var newShas []string
		newSeen := map[string]bool{}
		for _, rf := range refs {
			if rf.delete || newSeen[rf.sha] {
				continue
			}
			newSeen[rf.sha] = true
			newShas = append(newShas, rf.sha)
		}

		dek, err := s.DEKs.CurrentKey()
		if err != nil {
			return err
		}
		// Exclude everything already reachable from the remote's refs that we hold.
		rec, err := s.buildPack(dek, newShas, s.localRefShas(m))
		if err != nil {
			return err
		}

		newM := cloneManifest(m)
		newM.Generation = m.Generation + 1
		var pushedPackID string
		if rec != nil {
			newM.Packs = append(newM.Packs, *rec)
			pushedPackID = rec.PackID
		}
		for _, rf := range refs {
			if rf.delete {
				delete(newM.Refs, rf.dst)
				continue
			}
			newM.Refs[rf.dst] = rf.sha
			if newM.Head == "" && isHead(rf.dst) {
				newM.Head = rf.dst
			}
		}

		mblob, err := s.encryptManifest(newM)
		if err != nil {
			return err
		}
		if err := s.Store.WriteFile(store.ManifestFile, mblob); err != nil {
			return err
		}
		if _, err := s.Store.Commit(commitMsg); err != nil {
			return err
		}
		perr := s.Store.Push(false)
		if perr == nil {
			return s.commitState(newM.Generation, pushedPackID)
		}
		if errors.Is(perr, store.ErrNonFastForward) {
			lastErr = perr
			continue
		}
		return perr
	}
	return fmt.Errorf("store push rejected after %d retries (%v); another machine is pushing — re-run after `git pull`", maxPushRetries, lastErr)
}

// localRefShas returns the distinct ref-target shas in m that exist locally —
// the objects we can exclude from an incremental pack (we can only exclude what
// we hold).
func (s *Session) localRefShas(m *manifest.Manifest) []string {
	seen := map[string]bool{}
	var out []string
	for _, sha := range m.Refs {
		if !seen[sha] && s.repo.git.hasObject(sha) {
			seen[sha] = true
			out = append(out, sha)
		}
	}
	return out
}

// buildPack creates an incremental packfile of the objects reachable from
// newShas but not oldShas, encrypts it into the store under a fresh random pack
// id with the current DEK, and returns its manifest record. It returns (nil,
// nil) when there are no new objects to send.
func (s *Session) buildPack(dek []byte, newShas, oldShas []string) (*manifest.PackRecord, error) {
	if len(newShas) == 0 {
		return nil, nil
	}
	objectList, count, err := s.repo.revListObjects(newShas, oldShas)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	packID, err := crypto.RandomPackID()
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.repo.packObjects(objectList, pw)) }()
	chunks, werr := s.Store.WritePack(packID, dek, s.DEKs.Current, pr,
		s.Config.PackSplitBytes, s.Config.ChunkSize)
	pr.Close()
	if werr != nil {
		return nil, werr
	}
	return &manifest.PackRecord{
		PackID:        hex.EncodeToString(packID[:]),
		DEKGeneration: s.DEKs.Current,
		Chunks:        chunks,
		ObjectCount:   count,
	}, nil
}

// commitState records a newly-accepted manifest generation as the local
// high-water mark (S4) and optionally marks a pack as already present locally.
// It is the single writer of state.json on the push/fetch paths.
func (s *Session) commitState(gen uint64, importedPackID string) error {
	state, err := s.repo.LoadState()
	if err != nil {
		return err
	}
	if gen > state.LastGeneration {
		state.LastGeneration = gen
	}
	if importedPackID != "" {
		state.ImportedPacks[importedPackID] = true
	}
	return s.repo.SaveState(state)
}

// FetchAll decrypts the manifest, imports any not-yet-imported packs into the
// local object store, advances the rollback high-water mark, and returns the
// manifest (whose refs the helper then reports to git).
func (s *Session) FetchAll() (*manifest.Manifest, error) {
	m, err := s.ReadManifest()
	if err != nil {
		return nil, err
	}
	state, err := s.repo.LoadState()
	if err != nil {
		return nil, err
	}
	for _, p := range m.Packs {
		if state.ImportedPacks[p.PackID] {
			continue
		}
		dek, err := s.DEKs.Get(p.DEKGeneration)
		if err != nil {
			return nil, err
		}
		pr, pw := io.Pipe()
		go func(p manifest.PackRecord, dek []byte) {
			pw.CloseWithError(s.Store.ReadPack(p.PackID, p.Chunks, p.DEKGeneration, dek, pw))
		}(p, dek)
		ierr := s.repo.git.indexPack(pr)
		pr.Close()
		if ierr != nil {
			return nil, fmt.Errorf("importing pack %s: %w", p.PackID, ierr)
		}
		state.ImportedPacks[p.PackID] = true
	}
	if m.Generation > state.LastGeneration {
		state.LastGeneration = m.Generation
	}
	if err := s.repo.SaveState(state); err != nil {
		return nil, err
	}
	return m, nil
}

// --- helpers ---------------------------------------------------------------

func (r *Repo) revListObjects(newShas, oldShas []string) ([]byte, int, error) {
	args := []string{"rev-list", "--objects"}
	args = append(args, newShas...)
	for _, o := range oldShas {
		args = append(args, "^"+o)
	}
	out, err := r.git.run(args...)
	if err != nil {
		return nil, 0, fmt.Errorf("git rev-list: %w", err)
	}
	// One object per newline-terminated line.
	count := bytes.Count(out, []byte{'\n'})
	if len(out) > 0 && out[len(out)-1] != '\n' {
		count++ // tolerate a missing trailing newline
	}
	return out, count, nil
}

func (r *Repo) packObjects(objectList []byte, w io.Writer) error {
	cmd := r.git.command("pack-objects", "--stdout", "--delta-base-offset")
	cmd.Stdin = bytes.NewReader(objectList)
	cmd.Stdout = w
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git pack-objects: %v: %s", err, errb.String())
	}
	return nil
}

func cloneManifest(m *manifest.Manifest) *manifest.Manifest {
	out := manifest.New(m.Generation)
	out.Head = m.Head
	maps.Copy(out.Refs, m.Refs)
	out.Packs = append(out.Packs, m.Packs...)
	return out
}

func isHead(ref string) bool { return strings.HasPrefix(ref, headPrefix) }
