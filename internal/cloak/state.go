package cloak

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// State is the per-repo local trust state, persisted at GitDir/cloak/state.json.
// It implements rollback protection (S4): the client remembers the highest
// manifest generation it has ever accepted and refuses any store presenting a
// lower one.
type State struct {
	LastGeneration uint64 `json:"last_generation"`
	// ImportedPacks records pack ids already unpacked into the local repo, so
	// incremental fetches skip re-importing old history.
	ImportedPacks map[string]bool `json:"imported_packs,omitempty"`
}

func (r *Repo) statePath() string { return filepath.Join(r.stateDir, "state.json") }

// LoadState reads the local state, returning a zero state if none exists yet
// (first clone establishes the TOFU baseline).
func (r *Repo) LoadState() (*State, error) {
	data, err := os.ReadFile(r.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &State{ImportedPacks: map[string]bool{}}, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.ImportedPacks == nil {
		s.ImportedPacks = map[string]bool{}
	}
	return &s, nil
}

// SaveState persists the local state atomically.
func (r *Repo) SaveState(s *State) error {
	if err := os.MkdirAll(r.stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath())
}
