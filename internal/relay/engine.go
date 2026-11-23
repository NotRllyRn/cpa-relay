package relay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var ErrFetch = errors.New("relay fetch failed")
var ErrExport = errors.New("relay export unavailable")

// Source reads credentials only on authenticated exporter requests.
// Receiver Sink calls use the native instance host_ctx, never a temporary
// request callback ID. Stop joins the worker before releasing that context.
type Source interface {
	List() ([]Entry, error)
	Get(entry Entry) ([]byte, error)
	// Removed proves a formerly listed physical source is absent, not merely
	// hidden by host credential parsing. It must not read credential content.
	Removed(path string) (bool, error)
}
type Sink interface {
	Save(name string, raw []byte) (string, error)
	// CheckModels checks every exact runtime/model identity, then counts raw
	// active/available candidates. It does not prove upstream inference health.
	CheckModels(paths []string) (ModelStatus, error)
}

type ModelStatus struct {
	Available int
	Reason    string // fixed adapter code; never a raw host error
}

type Entry struct {
	Index, Name, Path            string
	Codex, RuntimeOnly, Disabled bool
	UnknownProvider              bool
}

type Engine struct {
	mu          sync.Mutex
	cfg         Config
	secretHash  [32]byte
	secret      string
	source      Source
	sink        Sink
	store       *store
	client      *http.Client
	transport   *http.Transport
	cancel      context.CancelFunc
	done        chan struct{}
	trigger     chan struct{}
	stopped     bool
	closed      bool
	reconciled  bool
	worker      atomic.Bool
	status      atomic.Pointer[Status]
	modelsUntil atomic.Int64
	quarantined atomic.Bool
	withdrawn   bool
	live        atomic.Bool
	serving     atomic.Bool
	deadline    atomic.Int64
	earliest    atomic.Int64
	lastAttempt string
	snapshot    *Snapshot
	// Diagnostic fields are protected by mu and copied into immutable status.
	modelReason           string
	availableAccounts     int
	modelCheckStartedAt   *time.Time
	modelCheckCompletedAt *time.Time
	modelCheckDurationMS  *int64
	lastSyncAt            *time.Time
	lastError             string
	lastErrorAt           *time.Time
	exported              *Status // safe metadata only; never retain exporter credentials
}

func New(c Config, secret string, source Source) (*Engine, error) {
	return newEngine(c, secret, source, nil)
}

// suppliedTransport is only an internal test seam, not an operator TLS bypass.
func newEngine(c Config, secret string, source Source, suppliedTransport *http.Transport) (*Engine, error) {
	s, err := openStore(c)
	if err != nil {
		return nil, err
	}
	e := &Engine{cfg: c, secret: secret, secretHash: sha256.Sum256([]byte("Bearer " + secret)), source: source, store: s, done: make(chan struct{}), trigger: make(chan struct{}, 1), lastAttempt: "starting"}
	e.live.Store(true)
	e.publishStatus()
	if c.Role == "receiver" {
		// Cached credentials never authorize startup. The worker first disables
		// old runtime state, then requires a strictly newer live snapshot.
		sink, ok := source.(Sink)
		if !ok {
			s.close()
			return nil, ErrStorage
		}
		e.sink = sink
		e.snapshot = s.state.Snapshot
		e.transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true, MaxIdleConnsPerHost: 1}
		if suppliedTransport != nil {
			e.transport = suppliedTransport
		}
		e.client = &http.Client{Transport: e.transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		ctx, cancel := context.WithCancel(context.Background())
		e.cancel = cancel
		e.worker.Store(true)
		go func() {
			defer close(e.done)
			defer e.worker.Store(false)
			reapDone := make(chan struct{})
			go func() { defer close(reapDone); e.reap(ctx) }()
			e.run(ctx)
			cancel()
			<-reapDone
		}()
	} else {
		close(e.done)
	}
	return e, nil
}

func (e *Engine) Authorized(h http.Header) bool {
	values := h.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 256 {
		return false
	}
	got := sha256.Sum256([]byte(values[0]))
	return subtle.ConstantTimeCompare(got[:], e.secretHash[:]) == 1
}

func (e *Engine) recoverWorker() {
	if recover() != nil {
		e.mu.Lock()
		e.setReady(false)
		e.quarantined.Store(true)
		e.recordAttempt("internal_error")
		e.publishStatus()
		e.mu.Unlock()
	}
}
func (e *Engine) reap(ctx context.Context) {
	defer e.recoverWorker()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.expire(time.Now())
		}
	}
}

func (e *Engine) initialize() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.publishStatus()
	dirty := false
	for _, id := range e.store.state.Managed {
		if e.store.clean(id) != nil {
			dirty = true
		}
	}
	err := e.store.withdrawRuntime(e.sink)
	if err == nil {
		e.withdrawn = true
	}
	if dirty {
		e.quarantined.Store(true)
		e.recordAttempt("integrity_failed")
	} else if err != nil {
		e.recordAttempt("cleanup_failed")
	}
	return err == nil && !dirty
}

func (e *Engine) run(ctx context.Context) {
	defer e.recoverWorker()
	// Instance host context only; panic unwinding must release every mutex.
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if e.initialize() {
			break
		}
		if e.quarantined.Load() {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 15*time.Second {
			backoff *= 2
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
		}
	}
	poll := time.NewTicker(time.Duration(e.cfg.PollSeconds) * time.Second)
	defer poll.Stop()
	e.pull(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			e.pull(ctx)
		case <-e.trigger:
			e.pull(ctx)
		}
	}
}

func (e *Engine) Trigger() bool {
	if !e.live.Load() || !e.worker.Load() || e.quarantined.Load() || e.cfg.Role != "receiver" {
		return false
	}
	select {
	case e.trigger <- struct{}{}:
	default:
	}
	return true
}

// Stop drains while callbacks remain available. Failed withdrawal retains both
// the inventory and store locks; another Stop retries the cleanup obligation.
func (e *Engine) Stop() error {
	e.live.Store(false)
	e.serving.Store(false)
	if e.cancel != nil {
		e.cancel()
	}
	<-e.done
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.publishStatus()
	e.stopped = true
	e.reconciled = false
	e.setReady(false)
	if e.closed {
		return nil
	}
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
	if e.cfg.Role == "receiver" && e.store.withdrawRuntime(e.sink) != nil {
		e.recordAttempt("cleanup_failed")
		return ErrStorage
	}
	e.store.close()
	e.closed = true
	e.secret = ""
	return nil
}

func (e *Engine) fresh(now time.Time) bool {
	s := e.snapshot
	if s == nil || !now.Before(s.GeneratedAt.Add(time.Duration(e.cfg.MaxStaleSeconds)*time.Second)) || s.GeneratedAt.After(now.Add(5*time.Second)) {
		return false
	}
	usable := 0
	for _, a := range s.Accounts {
		if a.Disabled {
			continue
		}
		if validateAccount(a, now, e.cfg.ExpirySkewSeconds) != nil {
			return false
		}
		usable++
	}
	return usable > 0
}

// Readiness and interception never wait for host callbacks or reconciliation.
func (e *Engine) Ready() bool {
	if !e.live.Load() || e.quarantined.Load() {
		return false
	}
	if e.cfg.Role == "exporter" {
		return true
	}
	now := time.Now().UnixNano()
	return e.serving.Load() && now < e.deadline.Load() && now >= e.earliest.Load() && now < e.modelsUntil.Load()
}
func (e *Engine) Gate() bool { return !e.live.Load() || (e.cfg.Role == "receiver" && !e.Ready()) }

// Must hold mu. Publish false before touching disk/runtime, and true only after
// every acknowledgement and integrity check. Deadline is conservative and
// independently checked on every readiness/interception request.
func (e *Engine) setReady(ready bool) {
	if !ready {
		e.serving.Store(false)
		return
	}
	deadline, _ := snapshotDeadline(e.snapshot, e.cfg)
	if deadline.IsZero() {
		e.serving.Store(false)
		return
	}
	e.deadline.Store(deadline.UnixNano())
	e.earliest.Store(e.snapshot.GeneratedAt.Add(-5 * time.Second).UnixNano())
	e.serving.Store(true)
}

// The observation lease expires even if a native callback blocks. Native calls
// are joined, not detached beyond the lifetime of the host context.
func (e *Engine) checkModels() {
	start := time.Now()
	startedUTC := start.UTC()
	e.modelCheckStartedAt = &startedUTC
	if !e.serving.Load() {
		e.modelReason = "models_pending"
	}
	// Publish the start before callbacks: status can explain a blocked check.
	e.publishStatus()
	paths := []string{}
	for _, a := range e.snapshot.Accounts {
		if !a.Disabled {
			paths = append(paths, filepath.Join(e.cfg.AuthDir, e.store.filename(a.CredentialID)))
		}
	}
	models, err := e.sink.CheckModels(paths)
	completed := time.Now()
	completedUTC := completed.UTC()
	duration := completed.Sub(start).Milliseconds()
	e.modelCheckCompletedAt, e.modelCheckDurationMS = &completedUTC, &duration
	e.availableAccounts = 0
	e.modelReason = models.Reason
	until := start.Add(3 * time.Second)
	switch {
	case err != nil:
		e.modelReason = "models_failed"
		e.recordAttempt("models_failed")
	case !completed.Before(until):
		e.modelReason = "model_check_slow"
		e.recordAttempt("models_pending")
	case len(paths) == 0:
		e.modelReason = "no_available_accounts"
		e.recordAttempt("models_pending")
	case !e.fresh(completed):
		e.modelReason = "snapshot_stale"
		e.recordAttempt("models_pending")
	case models.Available <= 0 || models.Available > len(paths):
		e.recordAttempt("models_pending")
	default:
		e.availableAccounts = models.Available
		e.modelsUntil.Store(until.UnixNano())
		e.setReady(true)
		if e.lastAttempt == "models_failed" || e.lastAttempt == "models_pending" {
			e.recordAttempt("ok")
		}
		return
	}
	e.setReady(false)
}

func (e *Engine) expire(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.publishStatus()
	if e.stopped {
		return
	}
	if !e.quarantined.Load() && e.reconciled && e.fresh(now) {
		if e.store.audit(e.snapshot) == nil {
			e.checkModels()
			return
		}
		e.quarantined.Store(true)
		e.recordAttempt("integrity_failed")
	}
	e.reconciled = false
	e.setReady(false)
	e.publishStatus() // Containment may block; expose invalidation first.
	if e.withdrawn {
		return
	}
	if e.store.withdrawRuntime(e.sink) != nil {
		e.recordAttempt("cleanup_failed")
	} else {
		e.withdrawn = true
	}
}

func fetch(ctx context.Context, client *http.Client, endpoint, secret string, c Config) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Snapshot{}, ErrFetch
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Snapshot{}, ErrFetch
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || err != nil || media != "application/json" || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength > MaxBody {
		return Snapshot{}, ErrFetch
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil || len(raw) > MaxBody {
		return Snapshot{}, ErrFetch
	}
	snap, err := DecodeSnapshot(raw, c, time.Now())
	if err != nil {
		return Snapshot{}, ErrFetch
	}
	return snap, nil
}

func (e *Engine) pull(ctx context.Context) {
	// Keep containment retries alive, but never poll a terminally quarantined
	// receiver. Recheck after fetching in case quarantine began in flight.
	if !e.live.Load() || e.quarantined.Load() || ctx.Err() != nil {
		return
	}
	snap, err := fetch(ctx, e.client, e.cfg.Endpoint, e.secret, e.cfg)
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.publishStatus()
	if !e.live.Load() || e.stopped || e.quarantined.Load() || ctx.Err() != nil {
		return
	}
	if err != nil {
		e.recordAttempt("fetch_failed")
		return
	}
	if snap.Generation <= e.store.state.Watermark {
		e.recordAttempt("replay_rejected")
		return
	}
	// Validation is all-or-nothing. Failed fetches never apply removals.
	e.reconciled = false
	e.setReady(false)
	e.withdrawn = false
	e.publishStatus()
	if e.store.accept(snap) != nil {
		e.recordAttempt("apply_failed")
		return
	}
	e.snapshot = &snap
	if e.store.reconcile(snap, e.sink) != nil {
		e.recordAttempt("apply_failed")
		e.publishStatus()
		// Best effort containment of partial updates. Gate remains closed even if
		// cleanup fails; report that failure without exposing file names or tokens.
		if e.store.withdrawRuntime(e.sink) != nil {
			e.recordAttempt("cleanup_failed")
		} else {
			e.withdrawn = true
		}
		return
	}
	e.recordAttempt("ok")
	e.reconciled = true
	synced := time.Now().UTC()
	e.lastSyncAt = &synced
	e.checkModels()
}

func (e *Engine) Export(now time.Time) (raw []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if err != nil {
			e.recordAttempt("export_failed")
		}
		e.publishStatus()
	}()
	if e.stopped || e.cfg.Role != "exporter" || e.source == nil {
		return nil, ErrExport
	}
	now = now.UTC()
	if now.UnixNano() <= e.store.state.Watermark {
		return nil, ErrExport
	}
	entries, err := e.source.List()
	if err != nil {
		return nil, ErrExport
	}
	entries, err = discoverSources(entries)
	if err != nil {
		return nil, ErrExport
	}
	s := Snapshot{Version: 2, Generation: now.UnixNano(), GeneratedAt: now, Accounts: []Account{}}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !entry.Codex || entry.RuntimeOnly {
			continue
		}
		raw, err := e.source.Get(entry)
		if err != nil {
			return nil, ErrExport
		}
		// Explicitly disabled records withdraw even when their token has become
		// unusable. Still require valid duplicate-free JSON and Codex type.
		m, err := sourceObject(raw)
		if err != nil {
			return nil, ErrExport
		}
		var kind string
		var disabled bool
		if json.Unmarshal(m["type"], &kind) != nil || kind != "codex" {
			return nil, ErrExport
		}
		if v, ok := m["disabled"]; ok {
			if string(v) == "null" || json.Unmarshal(v, &disabled) != nil {
				return nil, ErrExport
			}
		}
		if entry.Disabled || disabled {
			continue
		}
		a, err := Sanitize(raw)
		if err != nil || !accountFieldsValid(a) {
			return nil, ErrExport
		}
		a.CredentialID = credentialID(entry.Path)
		if seen[a.CredentialID] {
			return nil, ErrExport
		}
		seen[a.CredentialID] = true
		expiry, err := a.expires()
		if err != nil {
			return nil, ErrExport
		}
		// Well-formed expired credentials are absent from the full snapshot.
		if !now.Add(time.Duration(e.cfg.ExpirySkewSeconds) * time.Second).Before(expiry) {
			continue
		}
		if validateAccount(a, now, e.cfg.ExpirySkewSeconds) != nil {
			return nil, ErrExport
		}
		s.Accounts = append(s.Accounts, a)
	}
	// Detect additions, removals, reindexing and disabling during the read pass.
	// A list/read error is never converted into an authoritative empty snapshot.
	after, err := e.source.List()
	if err != nil {
		return nil, ErrExport
	}
	after, err = discoverSources(after)
	if err != nil || !sameSources(entries, after) {
		return nil, ErrExport
	}
	paths := make([]string, 0, len(entries))
	present := make(map[string]bool, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
		present[entry.Path] = true
	}
	for _, path := range e.store.state.SourcePaths {
		if present[path] {
			continue
		}
		removed, err := e.source.Removed(path)
		if err != nil || !removed {
			return nil, ErrExport
		}
	}
	sort.Slice(s.Accounts, func(i, j int) bool { return s.Accounts[i].CredentialID < s.Accounts[j].CredentialID })
	raw, err = json.Marshal(s)
	if err != nil || len(raw) > MaxBody-16384 {
		return nil, ErrExport
	}
	st := e.store.state
	st.Watermark = s.Generation
	st.SourcePaths = paths
	if e.store.save(st) != nil {
		return nil, ErrExport
	}
	generated := s.GeneratedAt.UTC()
	deadline, reason := snapshotDeadline(&s, e.cfg)
	e.exported = &Status{Accounts: len(s.Accounts), GeneratedAt: &generated, FreshUntil: &deadline, expiryReason: reason}
	synced := time.Now().UTC()
	e.lastSyncAt = &synced
	e.recordAttempt("ok")
	return raw, nil
}
