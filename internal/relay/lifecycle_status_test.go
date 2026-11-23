package relay

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type statusBlockedSink struct {
	Sink
	entered, release chan struct{}
}

func (s statusBlockedSink) Save(n string, b []byte) (string, error) {
	close(s.entered)
	<-s.release
	return s.Sink.Save(n, b)
}
func TestStatusIntegrityWhileWithdrawalBlocked(t *testing.T) {
	e, h := statusEngine(t)
	entered, release := make(chan struct{}), make(chan struct{})
	e.mu.Lock()
	e.sink = statusBlockedSink{h, entered, release}
	e.mu.Unlock()
	path := filepath.Join(e.cfg.AuthDir, e.store.filename(e.snapshot.Accounts[0].CredentialID))
	if err := os.WriteFile(path, []byte(`{"refresh_token":"synthetic"}`), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { e.expire(time.Now()); close(done) }()
	<-entered
	got := e.Status()
	close(release)
	<-done
	e.mu.Lock()
	e.sink = h
	e.mu.Unlock()
	t.Logf("during blocked containment: ready=%v reason=%q synced=%d available=%d", got.Ready, got.Reason, got.SynchronizedAccounts, got.AvailableAccounts)
	if got.Ready || got.Reason != "integrity_failed" || got.SynchronizedAccounts != 0 {
		t.Errorf("integrity invalidation not published before withdrawal")
	}
}

func TestStatusReconcileReasonAfterHistoricalFetchFailure(t *testing.T) {
	e, _ := statusEngine(t)
	e.mu.Lock()
	e.recordAttempt("fetch_failed")
	e.reconciled = false
	e.setReady(false)
	e.withdrawn = false
	e.publishStatus()
	e.mu.Unlock()
	got := e.Status()
	t.Logf("during newer reconciliation after failed fetch: reason=%q last_attempt=%q", got.Reason, got.LastAttempt)
	if got.Reason != "synchronizing" {
		t.Error("historical fetch result used as current reconciliation reason")
	}
}
