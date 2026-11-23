package relay

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mockHost models the important non-transactional CPA contract: a disk write
// happens before runtime acknowledgement, and failed updates can leave bytes.
type mockHost struct {
	mu            sync.Mutex
	dir           string
	runtime       map[string]Account
	failActive    bool
	failDisabled  bool
	contaminate   bool
	beforeActive  func()
	modelsMissing bool
	modelsErr     bool
	saves         int
	beforeModels  func()
}

func diskHost(dir string) *mockHost              { return &mockHost{dir: dir, runtime: map[string]Account{}} }
func (h *mockHost) List() ([]Entry, error)       { return nil, errors.New("unexpected read callback") }
func (h *mockHost) Removed(string) (bool, error) { return true, nil }
func (h *mockHost) Get(Entry) ([]byte, error)    { return nil, errors.New("unexpected read callback") }
func (h *mockHost) Save(name string, raw []byte) (string, error) {
	var a Account
	if json.Unmarshal(raw, &a) != nil {
		return "", ErrStorage
	}
	h.mu.Lock()
	h.saves++
	hook := h.beforeActive
	fail := h.failActive
	failDisabled := h.failDisabled
	dirty := h.contaminate
	h.mu.Unlock()
	path := filepath.Join(h.dir, name)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return "", err
	}
	if !a.Disabled && hook != nil {
		hook()
	}
	if (!a.Disabled && fail) || (a.Disabled && failDisabled) {
		return "", ErrStorage
	}
	if !a.Disabled && dirty {
		var m map[string]any
		json.Unmarshal(raw, &m)
		m["refresh_token"] = "must-not-adopt"
		b, _ := json.Marshal(m)
		os.WriteFile(path, b, 0600)
	}
	h.mu.Lock()
	h.runtime[name] = a
	h.mu.Unlock()
	return path, nil
}
func (h *mockHost) CheckModels(paths []string) (ModelStatus, error) {
	h.mu.Lock()
	hook := h.beforeModels
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.modelsErr {
		return ModelStatus{}, ErrStorage
	}
	if h.modelsMissing || len(paths) == 0 {
		return ModelStatus{Reason: "models_pending"}, nil
	}
	for _, p := range paths {
		a, ok := h.runtime[filepath.Base(p)]
		if !ok || a.Disabled {
			return ModelStatus{Reason: "models_pending"}, nil
		}
	}
	return ModelStatus{Available: len(paths), Reason: "ready"}, nil
}

func (h *mockHost) disabled(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runtime[name].Disabled
}

func TestRuntimeAcknowledgementAndRemovalBeforeReadiness(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	h := diskHost(c.AuthDir)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.beforeActive = func() { once.Do(func() { close(entered) }); <-release }
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no background save callback")
	}
	// Public readiness and request interception must not block or authorize a
	// request while the worker waits for synchronous runtime acknowledgement.
	if e.Ready() || !e.Gate() {
		t.Fatal("ready before runtime acknowledgement")
	}
	close(release)
	wait(t, e.Ready)
	h.mu.Lock()
	h.beforeActive = nil
	h.mu.Unlock()
	empty := snapshot(time.Now().Add(time.Second))
	f.set(t, empty)
	e.Trigger()
	wait(t, func() bool { return e.Status().GeneratedAt != nil && e.Status().GeneratedAt.Equal(empty.GeneratedAt) })
	if e.Ready() || !e.Gate() {
		t.Fatal("empty snapshot ready")
	}
	name := e.store.filename(credentialID("acct-a"))
	if !h.disabled(name) {
		t.Fatal("physical removal without runtime disable acknowledgement")
	}
	if _, err := os.Stat(filepath.Join(c.AuthDir, name)); !os.IsNotExist(err) {
		t.Fatal("owned file not removed")
	}
	e.Stop()
}

func TestRuntimeUpdateErrorAndConcurrentContaminationFailReadiness(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		t.Run(map[bool]string{false: "runtime failure", true: "concurrent contamination"}[dirty], func(t *testing.T) {
			f := newFixture(t)
			c := diskConfig(t, "receiver")
			c.Endpoint = f.server.URL + SnapshotPath
			h := diskHost(c.AuthDir)
			h.failActive = !dirty
			h.contaminate = dirty
			f.set(t, snapshot(time.Now(), "acct-a"))
			e, err := newEngine(c, secret(), h, f.transport())
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			wait(t, func() bool { return e.Status().LastAttempt == "apply_failed" })
			if e.Ready() || !e.Gate() {
				t.Fatal("unsafe runtime state ready")
			}
			if !h.disabled(e.store.filename(credentialID("acct-a"))) {
				t.Fatal("failed update not synchronously disabled")
			}
		})
	}
}

func TestContaminatedOwnedRecordRejected(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	h := diskHost(c.AuthDir)
	snap := snapshot(time.Now(), "acct-a")
	if s.accept(snap) != nil || s.reconcile(snap, h) != nil {
		t.Fatal("initial reconcile")
	}
	path := filepath.Join(c.AuthDir, s.filename(credentialID("acct-a")))
	a := snap.Accounts[0]
	var m map[string]any
	json.Unmarshal(marshal(t, a), &m)
	m["siwc"] = map[string]string{"refresh_token": "must-not-adopt"}
	os.WriteFile(path, marshal(t, m), 0600)
	if s.reconcile(snapshot(time.Now().Add(time.Second), "acct-a"), h) == nil {
		t.Fatal("contaminated owned record adopted")
	}
	if s.audit(&snap) == nil {
		t.Fatal("integrity audit missed contamination")
	}
	if s.withdrawRuntime(h) != nil {
		t.Fatal("could not disable contaminated owned record")
	}
	if !h.disabled(s.filename(credentialID("acct-a"))) {
		t.Fatal("contaminated runtime still enabled")
	}
}
