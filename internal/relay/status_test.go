package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStatusSeparatesSynchronizedAccountsFromAvailabilityAndErrors(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	h := diskHost(c.AuthDir)
	h.modelsMissing = true
	f.set(t, snapshot(time.Now(), "acct-a", "acct-b"))
	e, err := newEngine(c, secret(), h, f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, func() bool { return e.Status().LastAttempt == "models_pending" })
	first := e.Status()
	if first.Ready || first.Reason != "models_pending" || first.Accounts != 2 || first.SynchronizedAccounts != 2 || first.AvailableAccounts != 0 {
		t.Fatalf("synchronization hidden by pending models: %+v", first)
	}
	if first.LastSyncAt == nil || first.GeneratedAt == nil || first.FreshUntil == nil || first.SnapshotAgeSeconds == nil || first.ModelCheckStartedAt == nil || first.ModelCheckCompletedAt == nil || first.ModelCheckDurationMS == nil || first.ModelCheckValidUntil != nil {
		t.Fatal("missing or invented observation/freshness timestamps")
	}
	f.reply.Store(&httpReply{status: http.StatusServiceUnavailable, content: "application/json", body: []byte(`{"error":"private upstream detail"}`)})
	e.Trigger()
	wait(t, func() bool { return e.Status().LastAttempt == "fetch_failed" })
	failed := e.Status()
	if failed.LastError != "fetch_failed" || failed.LastErrorAt == nil || !failed.LastSyncAt.Equal(*first.LastSyncAt) || !failed.GeneratedAt.Equal(*first.GeneratedAt) {
		t.Fatal("failed fetch changed successful sync time or lost safe error")
	}
	h.mu.Lock()
	h.modelsMissing = false
	h.mu.Unlock()
	f.set(t, snapshot(time.Now(), "acct-a", "acct-b"))
	e.Trigger()
	wait(t, func() bool { return e.Status().Ready })
	recovered := e.Status()
	if recovered.Reason != "ready" || recovered.AvailableAccounts != 2 || recovered.SynchronizedAccounts != 2 || recovered.LastAttempt != "ok" || recovered.LastError != "fetch_failed" || !recovered.LastSyncAt.After(*first.LastSyncAt) || recovered.ModelCheckValidUntil == nil {
		t.Fatalf("recovery lost counts or historical error: %+v", recovered)
	}
	raw, _ := json.Marshal(recovered)
	for _, private := range []string{"acct-a", "acct-b", secret(), c.AuthDir, c.StateDir, "private upstream detail"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("status exposed private data")
		}
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	stopped := e.Status()
	if stopped.Reason != "stopped" || stopped.Ready || stopped.SynchronizedAccounts != 0 || stopped.Accounts != 0 || stopped.AvailableAccounts != 0 {
		t.Fatalf("drain kept active counts: %+v", stopped)
	}
}

// Use a real store/reconciliation but no worker clock, so expiry assertions do
// not race with cleanup. Stop still performs the normal runtime withdrawal.
func statusEngine(t *testing.T) (*Engine, *mockHost) {
	t.Helper()
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	h := diskHost(c.AuthDir)
	snap := snapshot(time.Now(), "acct-a")
	if s.accept(snap) != nil || s.reconcile(snap, h) != nil {
		s.close()
		t.Fatal("reconcile fixture")
	}
	done := make(chan struct{})
	close(done)
	e := &Engine{cfg: c, store: s, sink: h, snapshot: &snap, reconciled: true, lastAttempt: "ok", done: done}
	e.live.Store(true)
	e.mu.Lock()
	e.checkModels()
	e.publishStatus()
	e.mu.Unlock()
	t.Cleanup(func() {
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	})
	return e, h
}

func TestStatusAppliesIndependentFreshnessAndLeaseDeadlines(t *testing.T) {
	for _, name := range []string{"model_check_expired", "snapshot_stale", "credential_expired"} {
		t.Run(name, func(t *testing.T) {
			e, _ := statusEngine(t)
			if !e.Ready() {
				t.Fatal("fixture unready")
			}
			e.mu.Lock()
			switch name {
			case "model_check_expired":
				e.modelsUntil.Store(time.Now().Add(-time.Second).UnixNano())
			case "snapshot_stale":
				e.snapshot.GeneratedAt = time.Now().Add(-time.Duration(e.cfg.MaxStaleSeconds+1) * time.Second)
				e.setReady(true)
			case "credential_expired":
				e.snapshot.Accounts[0].Expired = time.Now().Add(time.Duration(e.cfg.ExpirySkewSeconds-1) * time.Second).UTC().Format(time.RFC3339Nano)
				e.setReady(true)
			}
			e.publishStatus()
			e.mu.Unlock()
			got := e.Status()
			if got.Ready || got.Reason != name || got.AvailableAccounts != 0 || got.SynchronizedAccounts != 1 || !e.Gate() {
				t.Fatalf("deadline not reflected: %+v", got)
			}
		})
	}
}

func TestStatusMeasuresSlowAndFailedModelChecks(t *testing.T) {
	e, h := statusEngine(t)
	h.beforeModels = func() { time.Sleep(3 * time.Second) }
	e.mu.Lock()
	e.checkModels()
	e.publishStatus()
	e.mu.Unlock()
	slow := e.Status()
	if slow.Ready || slow.Reason != "model_check_slow" || slow.AvailableAccounts != 0 || slow.ModelCheckDurationMS == nil || *slow.ModelCheckDurationMS < 3000 || !slow.ModelCheckCompletedAt.After(*slow.ModelCheckStartedAt) {
		t.Fatalf("slow check not explained: %+v", slow)
	}
	h.beforeModels = nil
	h.modelsErr = true
	e.mu.Lock()
	e.checkModels()
	e.publishStatus()
	e.mu.Unlock()
	failed := e.Status()
	if failed.Ready || failed.Reason != "models_failed" || failed.LastError != "models_failed" || failed.LastErrorAt == nil {
		t.Fatalf("failed check not explained: %+v", failed)
	}
}

func TestExporterStatusKeepsOnlySafeSnapshotMetadata(t *testing.T) {
	now := time.Now().UTC()
	c := diskConfig(t, "exporter")
	source := fakeSource{entries: []Entry{{Index: "a", Name: "a.json", Path: "/fixture/a.json", Codex: true}}, raw: map[string][]byte{"a": marshal(t, account(now, "acct-a"))}}
	e, err := New(c, secret(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	if _, err = e.Export(now); err != nil {
		t.Fatal(err)
	}
	first := e.Status()
	if !first.Ready || first.Accounts != 1 || first.SynchronizedAccounts != 0 || first.AvailableAccounts != 0 || first.GeneratedAt == nil || first.FreshUntil == nil || first.LastSyncAt == nil {
		t.Fatalf("export telemetry missing: %+v", first)
	}
	if e.snapshot != nil {
		t.Fatal("status retained exporter credentials")
	}
	e.mu.Lock()
	e.source = fakeSource{err: ErrExport}
	e.mu.Unlock()
	if _, err = e.Export(time.Now()); err != ErrExport {
		t.Fatal("export should fail")
	}
	failed := e.Status()
	if failed.LastError != "export_failed" || failed.LastErrorAt == nil || !failed.LastSyncAt.Equal(*first.LastSyncAt) || failed.Accounts != 1 {
		t.Fatalf("failed export changed successful metadata: %+v", failed)
	}
}
