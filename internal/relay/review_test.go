package relay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExporterRejectsMalformedActiveCodexFields(t *testing.T) {
	now := time.Now()
	for _, bad := range []string{
		`"access_token":123`, `"expired":[]`, `"email":{}`, `"disabled":"bad"`, `"plan_type":false`, `"type":null`,
		`"access_token":null`, `"email":null`, `"disabled":null`, `"plan_type":null`,
		`"account_id":123`, `"account_id":null`, `"account_id":"../unsafe"`,
	} {
		t.Run(bad, func(t *testing.T) {
			var other, patch map[string]any
			json.Unmarshal(marshal(t, account(now, "acct-a")), &other)
			json.Unmarshal([]byte(`{`+bad+`}`), &patch)
			for k, v := range patch {
				other[k] = v
			}
			c := diskConfig(t, "exporter")
			src := fakeSource{entries: []Entry{{Index: "a", Name: "a.json", Path: "/auth/a.json", Codex: true}, {Index: "b", Name: "b.json", Path: "/auth/b.json", Codex: true}}, raw: map[string][]byte{"a": marshal(t, account(now, "acct-a")), "b": marshal(t, other)}}
			e, err := New(c, secret(), src)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			if _, err = e.Export(now); err != ErrExport {
				t.Fatal("malformed active Codex credential did not fail closed")
			}
		})
	}
	valid := strings.TrimSuffix(string(marshal(t, account(now, "acct-a"))), "}")
	for _, raw := range []string{`{}`, `[]`, valid + `,"account_id":"acct-b"}`, valid + `,"ACCOUNT_ID":"acct-a"}`, valid + `,"x":{"a":1,"a":2}}`} {
		a, err := Sanitize([]byte(raw))
		if err == nil && accountFieldsValid(a) {
			t.Fatal("ambiguous or invalid identity accepted")
		}
	}
}

func TestDelayedModelsAndDisappearanceGateWithoutRewriting(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	h := diskHost(c.AuthDir)
	h.modelsMissing = true
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, func() bool { return e.Status().LastAttempt == "models_pending" })
	if e.Ready() || !e.Gate() {
		t.Fatal("save acknowledgement opened gate without models")
	}
	h.mu.Lock()
	h.modelsMissing = false
	h.failActive = true
	h.failDisabled = true
	h.mu.Unlock()
	// A periodic observation, not a new snapshot or rewrite, must open admission.
	wait(t, e.Ready)
	h.mu.Lock()
	h.modelsMissing = true
	h.mu.Unlock()
	wait(t, func() bool { return !e.Ready() })
	if !e.Gate() {
		t.Fatal("model disappearance did not close gate")
	}
	h.mu.Lock()
	h.modelsMissing = false
	h.modelsErr = true
	h.mu.Unlock()
	wait(t, func() bool { return e.Status().LastAttempt == "models_failed" })
	h.mu.Lock()
	h.modelsErr = false
	h.failActive = false
	h.failDisabled = false
	h.mu.Unlock()
	wait(t, e.Ready)
}

func TestModelLeaseExpiresAndStatusDoesNotWaitForCallback(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	h := diskHost(c.AuthDir)
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, e.Ready)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var once sync.Once
	h.mu.Lock()
	h.beforeModels = func() { once.Do(func() { close(entered) }); <-release }
	h.mu.Unlock()
	// Shorten the lease so this regression does not sleep three seconds.
	e.modelsUntil.Store(time.Now().Add(50 * time.Millisecond).UnixNano())
	done := make(chan struct{})
	go func() { e.expire(time.Now()); close(done) }()
	<-entered
	statusDone := make(chan Status, 1)
	go func() { statusDone <- e.Status() }()
	select {
	case status := <-statusDone:
		if status.ModelCheckStartedAt == nil || status.ModelCheckCompletedAt == nil || !status.ModelCheckStartedAt.After(*status.ModelCheckCompletedAt) {
			unblock()
			t.Fatal("blocked observation start not published")
		}
	case <-time.After(time.Second):
		unblock()
		t.Fatal("status waited for models callback")
	}
	wait(t, func() bool { return !e.Ready() })
	if status := e.Status(); !e.Gate() || status.Reason != "model_check_expired" || status.AvailableAccounts != 0 {
		t.Fatal("blocked native callback extended model observation or hid its expiry")
	}
	unblock()
	<-done
}

func TestStopRetainsFailedCleanupAndRetries(t *testing.T) {
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
	name := e.store.filename(credentialID("acct-a"))
	h.mu.Lock()
	h.failDisabled = true
	h.mu.Unlock()
	if e.Stop() != ErrStorage || e.Stop() != ErrStorage {
		t.Fatal("failed stop lost cleanup error")
	}
	if e.Ready() || !e.Gate() || e.Trigger() {
		t.Fatal("failed drain admitted work")
	}
	if len(e.store.state.Managed) != 1 || e.closed {
		t.Fatal("failed drain abandoned inventory/store")
	}
	if other, err := openStore(c); err == nil {
		other.close()
		t.Fatal("failed drain released ownership locks")
	}
	if h.disabled(name) {
		t.Fatal("runtime disable unexpectedly succeeded")
	}
	h.mu.Lock()
	h.failDisabled = false
	h.mu.Unlock()
	if e.Stop() != nil || !h.disabled(name) {
		t.Fatal("retry did not call runtime disable")
	}
	if _, err := os.Stat(filepath.Join(c.AuthDir, name)); !os.IsNotExist(err) {
		t.Fatal("drained file remains")
	}
	other, err := openStore(c)
	if err != nil {
		t.Fatal("successful retry retained locks")
	}
	other.close()
}

func TestStartupCleanupRetriesWithoutRestart(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	old := snapshot(time.Now().Add(-time.Second), "acct-a")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.accept(old) != nil {
		t.Fatal("seed inventory")
	}
	s.close()
	h := diskHost(c.AuthDir)
	h.failDisabled = true
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, func() bool { return e.Status().LastAttempt == "cleanup_failed" })
	if e.Ready() || !e.Gate() || f.calls.Load() != 0 {
		t.Fatal("startup cleanup failure admitted fetch/requests")
	}
	h.mu.Lock()
	h.failDisabled = false
	h.mu.Unlock()
	wait(t, e.Ready)
}

func TestRuntimeQuarantineStopsPollingButRetriesContainment(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	c.PollSeconds = 1
	h := diskHost(c.AuthDir)
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		h.mu.Lock()
		h.failDisabled = false
		h.mu.Unlock()
		if err := e.Stop(); err != nil {
			t.Error("cleanup failed")
		}
	}()
	wait(t, e.Ready)
	name := e.store.filename(credentialID("acct-a"))
	path := filepath.Join(c.AuthDir, name)
	h.mu.Lock()
	h.failDisabled = true
	h.mu.Unlock()
	if err := os.WriteFile(path, []byte(`{"refresh_token":"must-not-adopt"}`), 0600); err != nil {
		t.Fatal(err)
	}
	e.expire(time.Now())
	if !e.quarantined.Load() || e.Ready() || !e.Gate() {
		t.Fatal("runtime contamination did not quarantine admission")
	}
	calls := f.calls.Load()
	// Neither control nor the pre-fetch guard may wait for reconciliation.
	e.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		rejected := !e.Trigger()
		e.pull(context.Background())
		done <- rejected
	}()
	var rejected bool
	select {
	case rejected = <-done:
	case <-time.After(time.Second):
	}
	e.mu.Unlock()
	if !rejected {
		t.Fatal("quarantined poll accepted work or waited for the engine lock")
	}
	// Also exercise the actual poll worker with a previously queued request,
	// and allow multiple periodic poll/containment ticks to fire.
	e.trigger <- struct{}{}
	time.Sleep(2200 * time.Millisecond)
	if f.calls.Load() != calls {
		t.Fatal("terminal quarantine continued network polling")
	}
	if h.disabled(name) {
		t.Fatal("failed containment unexpectedly acknowledged")
	}
	h.mu.Lock()
	h.failDisabled = false
	h.mu.Unlock()
	wait(t, func() bool {
		_, err := os.Stat(path)
		return h.disabled(name) && os.IsNotExist(err)
	})
	if e.Trigger() || e.Ready() || !e.Gate() || f.calls.Load() != calls {
		t.Fatal("successful containment cleared terminal quarantine")
	}
}

func TestTerminatedWorkerRejectsTrigger(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	snap := snapshot(time.Now(), "acct-a")
	if s.accept(snap) != nil {
		t.Fatal("seed")
	}
	if err := os.WriteFile(filepath.Join(c.AuthDir, s.filename(credentialID("acct-a"))), []byte(`{"refresh_token":"not-adopted"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.close()
	e, err := New(c, secret(), diskHost(c.AuthDir))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	select {
	case <-e.done:
	case <-time.After(2 * time.Second):
		t.Fatal("integrity quarantine failed to end worker")
	}
	if e.Trigger() || e.Ready() || !e.Gate() {
		t.Fatal("terminated worker accepted action")
	}
}
