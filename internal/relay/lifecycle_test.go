package relay

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRemovalRequiresRuntimeDisableAcknowledgement(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	h := diskHost(c.AuthDir)
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	wait(t, e.Ready)
	name := e.store.filename("acct-a")
	h.mu.Lock()
	h.failDisabled = true
	h.mu.Unlock()
	f.set(t, snapshot(time.Now().Add(time.Second)))
	e.Trigger()
	wait(t, func() bool { return e.Status().LastAttempt == "cleanup_failed" })
	if e.Ready() || !e.Gate() {
		t.Fatal("failed removal authorized requests")
	}
	if h.disabled(name) {
		t.Fatal("mock unexpectedly acknowledged runtime disable")
	}
	if _, err := os.Stat(filepath.Join(c.AuthDir, name)); err != nil {
		t.Fatal("physically deleted before runtime disable acknowledgement")
	}
	h.mu.Lock()
	h.failDisabled = false
	h.mu.Unlock()
	if e.Stop() != nil {
		t.Fatal("shutdown cleanup retry")
	}
	if !h.disabled(name) {
		t.Fatal("shutdown did not disable retained runtime record")
	}
}

func TestShutdownJoinsInProgressNativeStyleCallback(t *testing.T) {
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
		t.Fatal("no callback")
	}
	stopped := make(chan struct{})
	go func() { e.Stop(); close(stopped) }()
	wait(t, func() bool { return !e.live.Load() })
	if e.Ready() || !e.Gate() {
		t.Fatal("shutdown admission open")
	}
	select {
	case <-stopped:
		t.Fatal("shutdown detached an active host callback")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown failed to join callback")
	}
	replacement, err := openStore(c)
	if err != nil {
		t.Fatal("state lock still held")
	}
	replacement.close()
}

func TestDeadlineAdmissionDoesNotWaitForCleanup(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), diskHost(c.AuthDir), f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, e.Ready)
	// A deadline check is independent of all disk, network and callback locks.
	e.mu.Lock()
	e.deadline.Store(time.Now().Add(-time.Second).UnixNano())
	if e.Ready() || !e.Gate() {
		t.Fatal("expired admission ignored conservative deadline")
	}
	e.mu.Unlock()
}
