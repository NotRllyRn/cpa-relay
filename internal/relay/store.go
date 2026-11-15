package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var ErrStorage = errors.New("relay storage unavailable")

// Bound outstanding cleanup plus the next full inventory, including on disk.
const maxManaged = MaxAccounts * 2

type diskState struct {
	Version     int       `json:"version"`
	Binding     string    `json:"binding"`
	Watermark   int64     `json:"watermark"`
	Snapshot    *Snapshot `json:"snapshot,omitempty"`
	Managed     []string  `json:"managed"`
	SourcePaths []string  `json:"source_paths,omitempty"` // exporter-only, private; never sent on wire
}

type store struct {
	root     *os.Root
	auth     *os.Root
	lock     *os.File
	authLock *os.File
	cfg      Config
	state    diskState
	applied  map[string]Account
}

func secureDir(path string, private bool, create bool) (*os.Root, error) {
	if create {
		if e := os.MkdirAll(path, 0700); e != nil {
			return nil, ErrStorage
		}
	}
	// Reject symlinked path components, including the final directory.
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, ErrStorage
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) {
			return nil, ErrStorage
		}
		// Root-owned sticky /tmp is acceptable; writable ordinary ancestors are not.
		if st.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return nil, ErrStorage
		}
		if p == path && (int(stat.Uid) != os.Geteuid() || st.Mode().Perm()&0022 != 0 || (private && st.Mode().Perm() != 0700)) {
			return nil, ErrStorage
		}
		if p == "/" {
			break
		}
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrStorage
	}
	return r, nil
}

func fileLock(root *os.Root, name string) (*os.File, error) {
	if st, e := root.Lstat(name); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return nil, ErrStorage
	} else if e != nil && !os.IsNotExist(e) {
		return nil, ErrStorage
	}
	f, e := root.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrStorage
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrStorage
	}
	return f, nil
}

func openStore(c Config) (_ *store, err error) {
	s := &store{cfg: c}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	s.root, err = secureDir(c.StateDir, true, true)
	if err != nil {
		return nil, ErrStorage
	}
	s.lock, err = fileLock(s.root, "lock")
	if err != nil {
		return nil, ErrStorage
	}
	s.state = diskState{Version: 2, Binding: c.binding(), Managed: []string{}}
	raw, e := readPrivate(s.root, "state.json")
	if e == nil {
		if strictJSON(raw, &s.state) != nil || s.state.Version != 2 || s.state.Binding != c.binding() || s.state.Watermark < 0 || len(s.state.Managed) > maxManaged {
			return nil, ErrStorage
		}
		if len(s.state.SourcePaths) > MaxAccounts || (c.Role != "exporter" && len(s.state.SourcePaths) != 0) {
			return nil, ErrStorage
		}
		paths := map[string]bool{}
		for _, path := range s.state.SourcePaths {
			if !sourcePathValid(path) || paths[path] {
				return nil, ErrStorage
			}
			paths[path] = true
		}
		seen := map[string]bool{}
		for _, id := range s.state.Managed {
			if !credentialPattern.MatchString(id) || seen[id] {
				return nil, ErrStorage
			}
			seen[id] = true
		}
		// Check the stored schema at its own generation, without applying a newly
		// increased skew. Cache validity never authorizes startup admission.
		cacheConfig := c
		cacheConfig.ExpirySkewSeconds = 0
		if s.state.Snapshot != nil && (s.state.Snapshot.Generation != s.state.Watermark || Validate(*s.state.Snapshot, cacheConfig, s.state.Snapshot.GeneratedAt) != nil) {
			return nil, ErrStorage
		}
	} else if !os.IsNotExist(e) {
		return nil, ErrStorage
	}
	if c.Role == "receiver" {
		s.auth, err = secureDir(c.AuthDir, false, false)
		if err != nil {
			return nil, ErrStorage
		}
		s.authLock, err = fileLock(s.auth, ".cpa-relay-"+c.ReceiverID+".lock")
		if err != nil {
			return nil, ErrStorage
		}
	}
	return s, nil
}

func readPrivate(root *os.Root, name string) ([]byte, error) {
	st, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > MaxBody {
		return nil, ErrStorage
	}
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxBody+1))
	if e != nil || len(b) > MaxBody {
		return nil, ErrStorage
	}
	return b, nil
}

func atomicWrite(root *os.Root, name string, raw []byte) error {
	if st, e := root.Lstat(name); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return ErrStorage
	} else if e != nil && !os.IsNotExist(e) {
		return ErrStorage
	}
	var nonce [12]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return ErrStorage
	}
	tmp := ".relay-" + hex.EncodeToString(nonce[:]) + ".tmp"
	f, e := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrStorage
	}
	defer root.Remove(tmp)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrStorage
	}
	if root.Rename(tmp, name) != nil {
		return ErrStorage
	}
	return syncDir(root)
}

func syncDir(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return ErrStorage
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrStorage
	}
	return nil
}

func (s *store) save(st diskState) error {
	if len(st.Managed) > maxManaged {
		return ErrStorage
	}
	b, e := json.Marshal(st)
	if e != nil || len(b) > MaxBody || atomicWrite(s.root, "state.json", b) != nil {
		return ErrStorage
	}
	s.state = st
	return nil
}

func (s *store) filename(id string) string {
	hash := sha256.Sum256([]byte(id))
	return fmt.Sprintf("cpa-relay-%s-%x.json", s.cfg.ReceiverID, hash)
}

// The write-ahead inventory is durable before any new credential is materialized.
// It makes cleanup safe after partial writes and process crashes.
func (s *store) accept(snap Snapshot) error {
	ids := map[string]bool{}
	for _, id := range s.state.Managed {
		ids[id] = true
	}
	for _, a := range snap.Accounts {
		// Never claim or overwrite a pre-existing file outside our durable inventory.
		if !ids[a.CredentialID] {
			if _, err := s.auth.Lstat(s.filename(a.CredentialID)); !os.IsNotExist(err) {
				return ErrStorage
			}
		}
		ids[a.CredentialID] = true
	}
	// Failed withdrawal can leave several generations owned. Reject more churn
	// before changing state; never persist an inventory that cannot be reopened
	// or truncate cleanup obligations to make room for new credentials.
	if len(ids) > maxManaged {
		return ErrStorage
	}
	managed := make([]string, 0, len(ids))
	for id := range ids {
		managed = append(managed, id)
	}
	sort.Strings(managed)
	st := diskState{Version: 2, Binding: s.cfg.binding(), Watermark: snap.Generation, Snapshot: &snap, Managed: managed}
	return s.save(st)
}

func (s *store) remove(id string) error {
	name := s.filename(id)
	st, e := s.auth.Lstat(name)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || !st.Mode().IsRegular() {
		return ErrStorage
	}
	if s.auth.Remove(name) != nil {
		return ErrStorage
	}
	return syncDir(s.auth)
}

// clean rejects refresh material, SIWC, arbitrary metadata, malformed files and
// symlinks. This namespace must never be used for normal CPA login credentials.
func (s *store) clean(id string) error {
	raw, err := readPrivate(s.auth, s.filename(id))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return ErrStorage
	}
	var a Account
	if strictJSON(raw, &a) != nil || a.CredentialID != id || a.Type != "codex" {
		return ErrStorage
	}
	return nil
}

func tombstone(id string) Account {
	return Account{Type: "codex", CredentialID: id, Expired: "1970-01-01T00:00:00Z", Disabled: true}
}

// Host save is not a transaction: first atomically stage the sanitized file,
// then require synchronous runtime acknowledgement, then verify persisted data.
// The request gate stays closed across the entire reconciliation.
func (s *store) saveCredential(a Account, sink Sink) error {
	name := s.filename(a.CredentialID)
	raw, err := json.Marshal(a)
	if err != nil || atomicWrite(s.auth, name, raw) != nil {
		return ErrStorage
	}
	path, err := sink.Save(name, raw)
	if err != nil || path != filepath.Join(s.cfg.AuthDir, name) {
		return ErrStorage
	}
	got, err := readPrivate(s.auth, name)
	if err != nil {
		return ErrStorage
	}
	var actual Account
	if strictJSON(got, &actual) != nil || actual != a {
		return ErrStorage
	}
	// Host save uses WriteFile; explicitly make its resulting bytes durable.
	f, err := s.auth.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrStorage
	}
	err = f.Sync()
	ce := f.Close()
	if err != nil || ce != nil {
		return ErrStorage
	}
	return syncDir(s.auth)
}

func (s *store) withdrawRuntime(sink Sink) error {
	s.applied = nil
	failed := false
	for _, id := range s.state.Managed {
		// Even a missing file can still have a runtime entry. Recreate a sanitized
		// disabled tombstone, synchronously disable runtime, and only then unlink.
		if s.saveCredential(tombstone(id), sink) != nil {
			failed = true
			continue
		}
		if s.remove(id) != nil {
			failed = true
		}
	}
	if failed {
		return ErrStorage
	}
	// All old records are synchronously disabled and physically absent. Keep the
	// snapshot/watermark, but retire the acknowledged ownership inventory.
	if len(s.state.Managed) > 0 {
		st := s.state
		st.Managed = []string{}
		return s.save(st)
	}
	return nil
}

func (s *store) reconcile(snap Snapshot, sink Sink) (err error) {
	defer func() {
		if err != nil {
			s.applied = nil
		}
	}()
	wanted := map[string]Account{}
	for _, a := range snap.Accounts {
		if !a.Disabled {
			wanted[a.CredentialID] = a
		}
	}
	unchanged := map[string]bool{}
	for id, a := range wanted {
		if old, ok := s.applied[id]; ok && old == a {
			unchanged[id] = true
		}
	}
	// Reject contamination before replacing any record. Never merge it into cache
	// or adopt it as an ordinary credential. Failure containment only disables it.
	for _, id := range s.state.Managed {
		if s.clean(id) != nil {
			return ErrStorage
		}
	}
	for _, id := range s.state.Managed {
		if unchanged[id] {
			raw, e := readPrivate(s.auth, s.filename(id))
			var got Account
			if e != nil || strictJSON(raw, &got) != nil || got != wanted[id] {
				return ErrStorage
			}
			continue
		}
		if s.saveCredential(tombstone(id), sink) != nil {
			return ErrStorage
		}
	}
	for _, id := range s.state.Managed {
		if _, active := wanted[id]; !active {
			if s.remove(id) != nil {
				return ErrStorage
			}
		}
	}
	for _, a := range snap.Accounts {
		if a.Disabled || unchanged[a.CredentialID] {
			continue
		}
		// Check again after tombstone callbacks: another writer may have interfered.
		if s.clean(a.CredentialID) != nil {
			return ErrStorage
		}
		if s.saveCredential(a, sink) != nil {
			return ErrStorage
		}
	}
	if s.audit(&snap) != nil {
		return ErrStorage
	}
	st := s.state
	st.Managed = make([]string, 0, len(snap.Accounts))
	for _, a := range snap.Accounts {
		st.Managed = append(st.Managed, a.CredentialID)
	}
	sort.Strings(st.Managed)
	if s.save(st) != nil {
		return ErrStorage
	}
	s.applied = wanted
	return nil
}

func (s *store) audit(snap *Snapshot) error {
	wanted := map[string]Account{}
	if snap != nil {
		for _, a := range snap.Accounts {
			if !a.Disabled {
				wanted[a.CredentialID] = a
			}
		}
	}
	for _, id := range s.state.Managed {
		raw, err := readPrivate(s.auth, s.filename(id))
		a, exists := wanted[id]
		if !exists {
			if !os.IsNotExist(err) {
				return ErrStorage
			}
			continue
		}
		var got Account
		if err != nil || strictJSON(raw, &got) != nil || got != a {
			return ErrStorage
		}
	}
	return nil
}

func (s *store) close() {
	if s.authLock != nil {
		s.authLock.Close()
	}
	if s.auth != nil {
		s.auth.Close()
	}
	if s.lock != nil {
		s.lock.Close()
	}
	if s.root != nil {
		s.root.Close()
	}
}

// ReservedNames is useful in operational tooling without exposing account IDs.
func ReservedNames(receiverID string, name string) bool {
	prefix := "cpa-relay-" + receiverID + "-"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
		return false
	}
	b, e := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json"))
	return e == nil && len(b) == sha256.Size
}
