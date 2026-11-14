package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSource struct {
	entries []Entry
	raw     map[string][]byte
	err     error
}

func (s fakeSource) List() ([]Entry, error) { return s.entries, s.err }
func (s fakeSource) Get(index string) ([]byte, error) {
	b, ok := s.raw[index]
	if !ok {
		return nil, errors.New("secret-source-error")
	}
	return b, nil
}
func TestExporterReadOnlySelectionAuthAndPersistence(t *testing.T) {
	now := time.Now().UTC()
	c := diskConfig(t, "exporter")
	c.Accounts = []string{"acct-a"}
	raw := strings.TrimSuffix(string(marshal(t, account(now, "acct-a"))), "}") + `,"refresh_token":"do-not-export","id_token":"do-not-export","metadata":{"secret":"do-not-export"}}`
	src := fakeSource{entries: []Entry{{Index: "a", Codex: true}, {Index: "b", Codex: true}, {Index: "other"}}, raw: map[string][]byte{"a": []byte(raw), "b": marshal(t, account(now, "acct-b"))}}
	e, err := New(c, secret(), src)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Authorized(http.Header{"Authorization": {"Bearer " + secret()}}) || e.Authorized(http.Header{"Authorization": {"Bearer wrong"}}) || e.Authorized(http.Header{"Authorization": {"Bearer " + secret(), "Bearer " + secret()}}) {
		t.Fatal("authentication failure")
	}
	b, err := e.Export(now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "do-not-export") || strings.Contains(string(b), "acct-b") {
		t.Fatal("selection/sanitization leak")
	}
	if _, err = e.Export(now); err == nil {
		t.Fatal("clock replay exported")
	}
	e.Stop()
	e, err = New(c, secret(), src)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	if _, err = e.Export(now); err == nil {
		t.Fatal("restart lost watermark")
	}
	if _, err = e.Export(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.source = fakeSource{err: errors.New("private detail")}
	e.mu.Unlock()
	if _, err = e.Export(now.Add(2 * time.Second)); err != ErrExport {
		t.Fatal("unsafe host error propagation")
	}
}

type httpReply struct {
	status            int
	body              []byte
	content, location string
}
type fixture struct {
	server  *httptest.Server
	reply   atomic.Pointer[httpReply]
	calls   atomic.Int32
	badAuth atomic.Bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.reply.Store(&httpReply{status: 503, content: "application/json", body: []byte(`{}`)})
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+secret() {
			f.badAuth.Store(true)
		}
		reply := f.reply.Load()
		w.Header().Set("Content-Type", reply.content)
		if reply.location != "" {
			w.Header().Set("Location", reply.location)
		}
		w.WriteHeader(reply.status)
		w.Write(reply.body)
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *fixture) set(t *testing.T, s Snapshot) {
	f.reply.Store(&httpReply{status: 200, content: "application/json", body: marshal(t, s)})
}
func (f *fixture) transport() *http.Transport {
	return f.server.Client().Transport.(*http.Transport).Clone()
}
func wait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestReceiverFullSnapshotsFailureReplayRemovalExpiryAndRestart(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	initial := snapshot(now, "acct-a", "acct-b")
	f.set(t, initial)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	e, err := newEngine(c, secret(), diskHost(c.AuthDir), f.transport())
	if err != nil {
		t.Fatal(err)
	}
	wait(t, e.Ready)
	if e.Gate() {
		t.Fatal("gate closed")
	}
	nameA := e.store.filename("acct-a")
	nameB := e.store.filename("acct-b")
	f.reply.Store(&httpReply{status: 500, content: "application/json", body: []byte("private response")})
	n := f.calls.Load()
	e.Trigger()
	wait(t, func() bool { return f.calls.Load() > n && e.Status().LastAttempt == "fetch_failed" })
	if !e.Ready() {
		t.Fatal("fresh state dropped after failed fetch")
	}
	if _, err := os.Stat(filepath.Join(c.AuthDir, nameB)); err != nil {
		t.Fatal("failure applied deletion")
	}
	f.set(t, initial)
	e.Trigger()
	wait(t, func() bool { return e.Status().LastAttempt == "replay_rejected" })
	if !e.Ready() {
		t.Fatal("replay rejuvenated or destroyed existing state")
	}
	next := snapshot(now.Add(time.Second), "acct-a")
	f.set(t, next)
	e.Trigger()
	wait(t, func() bool { return e.Status().LastAttempt == "ok" })
	wait(t, func() bool { _, err := os.Stat(filepath.Join(c.AuthDir, nameB)); return os.IsNotExist(err) })
	e.expire(now.Add(2 * time.Hour))
	if !e.Gate() {
		t.Fatal("expired gate open")
	}
	if _, err := os.Stat(filepath.Join(c.AuthDir, nameA)); !os.IsNotExist(err) {
		t.Fatal("expired credential retained")
	}
	// Cache keeps original generation. Stop/start never makes old/replayed state ready.
	if err = e.Stop(); err != nil {
		t.Fatal(err)
	}
	e, err = newEngine(c, secret(), diskHost(c.AuthDir), f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, func() bool { return e.Status().LastAttempt == "replay_rejected" })
	if e.Ready() || !e.Gate() {
		t.Fatal("cache/replay authorized startup")
	}
	if !e.Status().GeneratedAt.Equal(next.GeneratedAt) {
		t.Fatal("cache age reset")
	}
	f.set(t, snapshot(now.Add(2*time.Second), "acct-a"))
	e.Trigger()
	wait(t, e.Ready)
	if f.badAuth.Load() {
		t.Fatal("bearer missing")
	}
}

func TestReceiverStaleBoundaryAndJWTWithdraw(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	s := snapshot(now, "acct-a")
	s.Accounts[0].AccessToken = token(now.Add(120 * time.Second))
	f.set(t, s)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	c.MaxStaleSeconds = 30
	e, err := newEngine(c, secret(), diskHost(c.AuthDir), f.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	wait(t, e.Ready)
	e.mu.Lock()
	if e.fresh(now.Add(30 * time.Second)) {
		t.Fatal("stale boundary accepted")
	}
	if !e.fresh(now.Add(29 * time.Second)) {
		t.Fatal("premature stale")
	}
	e.cfg.MaxStaleSeconds = 3600
	if e.fresh(now.Add(61 * time.Second)) {
		t.Fatal("JWT skew ignored")
	}
	e.mu.Unlock()
	e.expire(now.Add(61 * time.Second))
	if e.Ready() {
		t.Fatal("expiry reopened gate")
	}
}

func TestFetchRejectsMalformedOversizeRedirectAndTLS(t *testing.T) {
	f := newFixture(t)
	c := protocolConfig()
	endpoint := f.server.URL + SnapshotPath
	client := &http.Client{Transport: f.transport(), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	var exfil atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { exfil.Add(1) }))
	defer destination.Close()
	for name, reply := range map[string]*httpReply{
		"invalid JSON":  {200, []byte(`{"version":`), "application/json", ""},
		"unknown field": {200, []byte(`{"refresh_token":"private"}`), "application/json", ""},
		"oversize":      {200, []byte(strings.Repeat("x", MaxBody+1)), "application/json", ""},
		"wrong type":    {200, []byte(`{}`), "text/html", ""},
		"redirect":      {302, nil, "application/json", destination.URL},
		"denied":        {401, []byte("private body"), "application/json", ""},
	} {
		t.Run(name, func(t *testing.T) {
			f.reply.Store(reply)
			if _, err := fetch(context.Background(), client, endpoint, secret(), c); err != ErrFetch {
				t.Fatal("accepted/unsafe error")
			}
		})
	}
	if exfil.Load() != 0 {
		t.Fatal("followed redirect/exfiltrated bearer")
	}
	f.set(t, snapshot(time.Now(), "acct-a"))
	if _, err := fetch(context.Background(), &http.Client{Timeout: time.Second}, endpoint, secret(), c); err != ErrFetch {
		t.Fatal("untrusted TLS accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetch(ctx, client, endpoint, secret(), c); err != ErrFetch {
		t.Fatal("cancellation ignored")
	}
}

func TestWriteErrorNeverReadyAndShutdownCleans(t *testing.T) {
	f := newFixture(t)
	c := diskConfig(t, "receiver")
	c.Endpoint = f.server.URL + SnapshotPath
	// Reserve a colliding file; the receiver must refuse ownership, not delete it.
	probe := &store{cfg: c}
	path := filepath.Join(c.AuthDir, probe.filename("acct-a"))
	os.WriteFile(path, []byte("manual"), 0600)
	f.set(t, snapshot(time.Now(), "acct-a"))
	e, err := newEngine(c, secret(), diskHost(c.AuthDir), f.transport())
	if err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { return e.Status().LastAttempt == "apply_failed" })
	if e.Ready() || !e.Gate() {
		t.Fatal("write error passed gate")
	}
	e.Stop()
	b, _ := os.ReadFile(path)
	if string(b) != "manual" {
		t.Fatal("collision deleted")
	}
}

func TestLifecycleCancellationAndConcurrentControls(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(entered) }); <-r.Context().Done() }))
	defer server.Close()
	c := diskConfig(t, "receiver")
	c.Endpoint = server.URL + SnapshotPath
	e, err := newEngine(c, secret(), diskHost(c.AuthDir), server.Client().Transport.(*http.Transport).Clone())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no fetch")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e.Ready()
				e.Gate()
				e.Status()
				e.Trigger()
			}
		}()
	}
	stopped := make(chan struct{})
	go func() { e.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel fetch")
	}
	wg.Wait()
	if e.Ready() || !e.Gate() {
		t.Fatal("shutdown gate open")
	}
	// A replacement can acquire the same store locks immediately after Stop.
	replacement, err := newEngine(c, secret(), diskHost(c.AuthDir), server.Client().Transport.(*http.Transport).Clone())
	if err != nil {
		t.Fatal(err)
	}
	replacement.Stop()
}
