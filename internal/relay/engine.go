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
	Get(index string) ([]byte, error)
}
type Sink interface {
	Save(name string, raw []byte) (string, error)
	// ModelsReady confirms active runtime entries and registered models for every
	// exact managed path, not upstream inference or quota health.
	ModelsReady(paths []string) (bool, error)
}

type Entry struct {
	Index                        string
	Codex, RuntimeOnly, Disabled bool
}

type Status struct {
	Role        string     `json:"role"`
	Ready       bool       `json:"ready"`
	State       string     `json:"state"`
	LastAttempt string     `json:"last_attempt"`
	Accounts    int        `json:"accounts"`
	GeneratedAt *time.Time `json:"generated_at,omitempty"`
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
		e.lastAttempt = "internal_error"
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
		e.lastAttempt = "integrity_failed"
	} else if err != nil {
		e.lastAttempt = "cleanup_failed"
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
	e.setReady(false)
	if e.closed {
		return nil
	}
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
	if e.cfg.Role == "receiver" && e.store.withdrawRuntime(e.sink) != nil {
		e.lastAttempt = "cleanup_failed"
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
	deadline := e.snapshot.GeneratedAt.Add(time.Duration(e.cfg.MaxStaleSeconds) * time.Second)
	for _, a := range e.snapshot.Accounts {
		if a.Disabled {
			continue
		}
		exp, err := a.expires()
		if err != nil {
			e.serving.Store(false)
			return
		}
		exp = exp.Add(-time.Duration(e.cfg.ExpirySkewSeconds) * time.Second)
		if exp.Before(deadline) {
			deadline = exp
		}
	}
	e.deadline.Store(deadline.UnixNano())
	e.earliest.Store(e.snapshot.GeneratedAt.Add(-5 * time.Second).UnixNano())
	e.serving.Store(true)
}

// Must hold mu (except construction). Status never waits for native callbacks.
func (e *Engine) publishStatus() {
	s := Status{Role: e.cfg.Role, State: "starting", LastAttempt: e.lastAttempt}
	if e.snapshot != nil {
		t := e.snapshot.GeneratedAt
		s.GeneratedAt = &t
	}
	switch {
	case e.stopped && !e.closed:
		s.State = "cleanup_failed"
	case e.stopped:
		s.State = "stopped"
	case e.cfg.Role == "exporter":
		s.State = "exporter"
	case e.Ready():
		s.State = "ready"
		for _, a := range e.snapshot.Accounts {
			if !a.Disabled {
				s.Accounts++
			}
		}
	case e.lastAttempt == "apply_failed":
		s.State = "apply_failed"
	case e.snapshot != nil:
		s.State = "unready"
	}
	e.status.Store(&s)
}

func (e *Engine) Status() Status {
	s := *e.status.Load()
	s.Ready = e.Ready()
	if s.State == "ready" && !s.Ready {
		s.State = "unready"
	}
	return s
}

// The observation lease expires even if a native callback blocks. Native calls
// are joined, not detached beyond the lifetime of the host context.
func (e *Engine) checkModels() {
	start := time.Now()
	paths := []string{}
	for _, a := range e.snapshot.Accounts {
		if !a.Disabled {
			paths = append(paths, filepath.Join(e.cfg.AuthDir, e.store.filename(a.AccountID)))
		}
	}
	okay, err := e.sink.ModelsReady(paths)
	until := start.Add(3 * time.Second)
	if err != nil || !okay || len(paths) == 0 || !time.Now().Before(until) || !e.fresh(time.Now()) {
		e.setReady(false)
		if err != nil {
			e.lastAttempt = "models_failed"
		} else {
			e.lastAttempt = "models_pending"
		}
		return
	}
	e.modelsUntil.Store(until.UnixNano())
	e.setReady(true)
	if e.lastAttempt == "models_failed" || e.lastAttempt == "models_pending" {
		e.lastAttempt = "ok"
	}
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
		e.lastAttempt = "integrity_failed"
	}
	e.reconciled = false
	e.setReady(false)
	if e.withdrawn {
		return
	}
	if e.store.withdrawRuntime(e.sink) != nil {
		e.lastAttempt = "cleanup_failed"
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
		e.lastAttempt = "fetch_failed"
		return
	}
	if snap.Generation <= e.store.state.Watermark {
		e.lastAttempt = "replay_rejected"
		return
	}
	// Validation is all-or-nothing. Failed fetches never apply removals.
	e.reconciled = false
	e.setReady(false)
	e.withdrawn = false
	if e.store.accept(snap) != nil {
		e.lastAttempt = "apply_failed"
		return
	}
	e.snapshot = &snap
	if e.store.reconcile(snap, e.sink) != nil {
		e.lastAttempt = "apply_failed"
		// Best effort containment of partial updates. Gate remains closed even if
		// cleanup fails; report that failure without exposing file names or tokens.
		if e.store.withdrawRuntime(e.sink) != nil {
			e.lastAttempt = "cleanup_failed"
		} else {
			e.withdrawn = true
		}
		return
	}
	e.lastAttempt = "ok"
	e.reconciled = true
	e.checkModels()
}

func (e *Engine) Export(now time.Time) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped || e.cfg.Role != "exporter" || e.source == nil {
		return nil, ErrExport
	}
	now = now.UTC()
	if now.UnixNano() <= e.store.state.Watermark {
		return nil, ErrExport
	}
	entries, err := e.source.List()
	if err != nil || len(entries) > 4096 {
		return nil, ErrExport
	}
	s := Snapshot{Version: 1, Generation: now.UnixNano(), GeneratedAt: now, Accounts: []Account{}}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !entry.Codex || entry.RuntimeOnly {
			continue
		}
		raw, err := e.source.Get(entry.Index)
		if err != nil {
			return nil, ErrExport
		}
		id, err := SourceIdentity(raw)
		if err != nil {
			return nil, ErrExport
		}
		if !e.cfg.selected(id) {
			continue
		}
		a, err := Sanitize(raw)
		if err != nil {
			return nil, ErrExport
		}
		if seen[a.AccountID] {
			return nil, ErrExport
		}
		seen[a.AccountID] = true
		a.Disabled = a.Disabled || entry.Disabled
		expiry, err := a.expires()
		if err != nil {
			return nil, ErrExport
		}
		// Expired selected accounts are absent from this full snapshot.
		if !now.Add(time.Duration(e.cfg.ExpirySkewSeconds) * time.Second).Before(expiry) {
			continue
		}
		if validateAccount(a, now, e.cfg.ExpirySkewSeconds) != nil {
			return nil, ErrExport
		}
		s.Accounts = append(s.Accounts, a)
	}
	sort.Slice(s.Accounts, func(i, j int) bool { return s.Accounts[i].AccountID < s.Accounts[j].AccountID })
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxBody-16384 {
		return nil, ErrExport
	}
	st := e.store.state
	st.Watermark = s.Generation
	if e.store.save(st) != nil {
		return nil, ErrExport
	}
	return raw, nil
}
