package relay

import "time"

type Status struct {
	Role                  string     `json:"role"`
	Ready                 bool       `json:"ready"`
	State                 string     `json:"state"`
	Reason                string     `json:"reason"`
	LastAttempt           string     `json:"last_attempt"`
	Accounts              int        `json:"accounts"`
	SynchronizedAccounts  int        `json:"synchronized_accounts"`
	AvailableAccounts     int        `json:"available_accounts"`
	GeneratedAt           *time.Time `json:"generated_at,omitempty"`
	FreshUntil            *time.Time `json:"fresh_until,omitempty"`
	SnapshotAgeSeconds    *int64     `json:"snapshot_age_seconds,omitempty"`
	ModelCheckStartedAt   *time.Time `json:"model_check_started_at,omitempty"`
	ModelCheckCompletedAt *time.Time `json:"model_check_completed_at,omitempty"`
	ModelCheckDurationMS  *int64     `json:"model_check_duration_ms,omitempty"`
	ModelCheckValidUntil  *time.Time `json:"model_check_valid_until,omitempty"`
	LastSyncAt            *time.Time `json:"last_sync_at,omitempty"`
	LastError             string     `json:"last_error,omitempty"`
	LastErrorAt           *time.Time `json:"last_error_at,omitempty"`
	expiryReason          string
}

// Use the same boundary for admission and diagnostics. The caller owns snapshot access.
func snapshotDeadline(snapshot *Snapshot, cfg Config) (time.Time, string) {
	deadline := snapshot.GeneratedAt.Add(time.Duration(cfg.MaxStaleSeconds) * time.Second)
	reason := "snapshot_stale"
	for _, a := range snapshot.Accounts {
		if a.Disabled {
			continue
		}
		exp, err := a.expires()
		if err != nil {
			return time.Time{}, "credential_expired"
		}
		exp = exp.Add(-time.Duration(cfg.ExpirySkewSeconds) * time.Second)
		if exp.Before(deadline) {
			deadline, reason = exp, "credential_expired"
		}
	}
	return deadline, reason
}

// Must hold mu. Store only fixed codes, never native errors.
func (e *Engine) recordAttempt(code string) {
	e.lastAttempt = code
	switch code {
	case "starting", "ok", "models_pending":
		return
	}
	now := time.Now().UTC()
	e.lastError, e.lastErrorAt = code, &now
}

// Must hold mu (except construction). Status never waits for native callbacks.
func (e *Engine) publishStatus() {
	s := Status{Role: e.cfg.Role, State: "starting", Reason: "starting", LastAttempt: e.lastAttempt,
		ModelCheckStartedAt: e.modelCheckStartedAt, ModelCheckCompletedAt: e.modelCheckCompletedAt,
		ModelCheckDurationMS: e.modelCheckDurationMS, LastSyncAt: e.lastSyncAt,
		LastError: e.lastError, LastErrorAt: e.lastErrorAt}
	if e.snapshot != nil {
		generated := e.snapshot.GeneratedAt
		s.GeneratedAt = &generated
		deadline, reason := snapshotDeadline(e.snapshot, e.cfg)
		s.expiryReason = reason
		for _, a := range e.snapshot.Accounts {
			if a.Disabled {
				continue
			}
			if e.reconciled {
				s.Accounts++
			}
		}
		s.FreshUntil = &deadline
	}
	if e.exported != nil {
		s.Accounts, s.GeneratedAt, s.FreshUntil, s.expiryReason = e.exported.Accounts, e.exported.GeneratedAt, e.exported.FreshUntil, e.exported.expiryReason
	}
	if e.cfg.Role == "receiver" && e.reconciled {
		s.SynchronizedAccounts = s.Accounts
	}
	if until := e.modelsUntil.Load(); until > 0 {
		lease := time.Unix(0, until).UTC()
		s.ModelCheckValidUntil = &lease
	}
	switch {
	case e.stopped && !e.closed:
		s.State, s.Reason = "cleanup_failed", "cleanup_failed"
	case e.stopped:
		s.State, s.Reason = "stopped", "stopped"
	case e.quarantined.Load():
		s.State, s.Reason = "unready", e.lastAttempt
	case e.cfg.Role == "exporter":
		s.State, s.Reason = "exporter", "exporter"
	case e.Ready():
		s.State, s.Reason = "ready", e.modelReason
	case e.lastAttempt == "apply_failed" || e.lastAttempt == "cleanup_failed":
		s.State, s.Reason = e.lastAttempt, e.lastAttempt
	case e.reconciled:
		s.State, s.Reason = "unready", e.modelReason
	case e.snapshot != nil:
		s.State, s.Reason = "unready", e.lastAttempt
		if !e.withdrawn {
			s.Reason = "synchronizing"
		}
	case e.lastAttempt != "starting":
		s.Reason = e.lastAttempt
	}
	s.AvailableAccounts = e.availableAccounts
	s.Ready = e.Ready()
	e.status.Store(&s)
}

func (e *Engine) Status() Status {
	s := *e.status.Load()
	s.Ready = s.Ready && e.Ready()
	now := time.Now()
	if s.GeneratedAt != nil {
		age := int64(now.Sub(*s.GeneratedAt) / time.Second)
		if age < 0 {
			age = 0
		}
		s.SnapshotAgeSeconds = &age
	}
	if s.State == "ready" && !s.Ready {
		s.State = "unready"
	}
	if !s.Ready {
		s.AvailableAccounts = 0
		switch {
		case !e.live.Load() && s.State != "stopped" && s.State != "cleanup_failed":
			s.Reason = "stopping"
		case s.FreshUntil != nil && !now.Before(*s.FreshUntil) && !e.quarantined.Load() && s.State != "stopped" && s.State != "cleanup_failed":
			s.Reason = s.expiryReason
		case s.Reason == "ready" || s.Reason == "degraded":
			s.Reason = "model_check_expired"
		}
	}
	return s
}
