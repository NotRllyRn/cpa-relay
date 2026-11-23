(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const put = (id, value) => {
    const node = $(id), text = String(value);
    if (node.textContent !== text) node.textContent = text;
  };
  const PERIOD = 5000, TIMEOUT = 8000, MAX_BODY = 16384;
  const codes = new Set(('ready degraded no_available_accounts runtime_mismatch runtime_disabled models_pending models_failed model_check_slow model_check_expired snapshot_stale credential_expired starting synchronizing stopping stopped exporter fetch_failed replay_rejected apply_failed integrity_failed cleanup_failed internal_error export_failed settings_invalid settings_migration_required storage_unavailable disabled unconfigured configured unready ok').split(' '));
  const dates = ['generated_at', 'fresh_until', 'model_check_started_at', 'model_check_completed_at', 'model_check_valid_until', 'last_sync_at', 'last_error_at'];
  const counters = ['accounts', 'synchronized_accounts', 'available_accounts'];
  let key = '', data = null, observedAt = 0, observedMono = 0;
  let generation = 0, pending = null, pollTimer = null, clockTimer = null, paused = false;
  let failure = '', lastSemantic = '', lastPausedLease = false;

  const exact = value => value == null ? 'Not observed' : new Date(value).toISOString().replace('T', ' ').replace('Z', ' UTC');
  function duration(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + seconds % 60 + 's';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ' + Math.floor(seconds % 3600 / 60) + 'm';
    return Math.floor(seconds / 86400) + 'd ' + Math.floor(seconds % 86400 / 3600) + 'h';
  }
  function stamp(id, value, note) {
    put(id, exact(value));
    if (note) {
      const small = document.createElement('small');
      small.textContent = note;
      $(id).append(small);
    }
  }
  function announce(message, force = false) {
    if (force && $('announcement').textContent === message) $('announcement').textContent = '';
    put('announcement', message);
  }
  function validDate(value) {
    // Match UTC RFC3339 emitted by Go, including nanoseconds, and reject normalized invalid dates.
    if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value)) return false;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19);
  }
  function validate(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || typeof raw.ready !== 'boolean' || typeof raw.role !== 'string') throw new Error();
    const out = {ready: raw.ready, role: ['receiver', 'exporter', ''].includes(raw.role) ? raw.role : 'unknown'};
    for (const field of ['state', 'reason', 'last_attempt']) {
      if (typeof raw[field] !== 'string') throw new Error();
      out[field] = codes.has(raw[field]) ? raw[field] : 'unknown';
    }
    for (const field of counters) {
      if (!Number.isInteger(raw[field]) || raw[field] < 0 || raw[field] > 128) throw new Error();
      out[field] = raw[field];
    }
    for (const field of dates) {
      if (Object.hasOwn(raw, field)) {
        if (!validDate(raw[field])) throw new Error();
        out[field] = raw[field];
      }
    }
    for (const field of ['snapshot_age_seconds', 'model_check_duration_ms']) {
      if (Object.hasOwn(raw, field)) {
        if (!Number.isSafeInteger(raw[field]) || raw[field] < 0) throw new Error();
        out[field] = raw[field];
      }
    }
    if (Object.hasOwn(raw, 'last_error')) {
      if (typeof raw.last_error !== 'string') throw new Error();
      out.last_error = codes.has(raw.last_error) ? raw.last_error : 'unknown';
    }
    if (out.available_accounts > out.synchronized_accounts || (!out.ready && out.available_accounts !== 0)) throw new Error();
    if (out.role === 'receiver' && out.accounts !== out.synchronized_accounts) throw new Error();
    if (out.ready && out.role === 'receiver' && ((out.reason === 'ready' && out.available_accounts !== out.synchronized_accounts) || (out.reason === 'degraded' && out.available_accounts >= out.synchronized_accounts))) throw new Error();
    if (out.role === 'exporter' && (out.synchronized_accounts || out.available_accounts)) throw new Error();
    return out;
  }
  function knownDecision() {
    if (!data || data.role === 'unknown' || data.state === 'unknown' || data.reason === 'unknown') return false;
    if (!data.ready) return !['ready', 'degraded', 'exporter'].includes(data.reason);
    if (data.role === 'exporter') return data.state === 'exporter' && data.reason === 'exporter';
    if (data.role !== 'receiver') return false;
    return data.state === 'ready' && ['ready', 'degraded'].includes(data.reason) && data.available_accounts > 0 &&
      !!(data.generated_at && data.fresh_until && data.model_check_valid_until);
  }
  function view() {
    const age = data ? Math.max(0, (performance.now() - observedMono) / 1000) : null;
    const exporter = data?.role === 'exporter';
    const leaseElapsed = !!(data?.model_check_valid_until && Date.now() >= Date.parse(data.model_check_valid_until));
    const unknown = !knownDecision() || age > 15;
    const historical = unknown || leaseElapsed || !!failure;
    let title = 'Status unknown', reason = 'No valid status observation yet. Refresh status to read the latest admission result.', tone = 'neutral', symbol = '?';
    if (data && age > 15) reason = 'The last status observation is more than 15 seconds old. Current relay admission is unknown.';
    else if (data && !knownDecision()) reason = 'This status does not provide a recognized admission decision. Check the relay version and diagnostic details.';
    else if (exporter) {
      title = data.ready ? 'Exporter configured at last check' : 'Exporter not ready at last check';
      tone = data.ready ? 'success' : 'danger'; symbol = data.ready ? '✓' : '!';
      reason = data.ready ? 'Exporter configuration was ready to serve authenticated snapshots. Receiver health and delivery acknowledgement are not observed here.' : 'The exporter was not ready. Check the diagnostic reason and CPA plugin settings.';
    } else if (data?.ready) {
      const reduced = data.reason === 'degraded';
      title = reduced ? 'Ready at last check · reduced pool' : 'Ready at last check';
      tone = reduced ? 'warning' : 'success'; symbol = '✓';
      reason = reduced ? `${data.available_accounts} of ${data.synchronized_accounts} synchronized accounts were runtime candidates at this check. ${data.synchronized_accounts - data.available_accounts} did not qualify.` : 'Runtime identity and model registration checks passed. Relay admission was open at this status check.';
    } else if (data) {
      tone = 'danger'; symbol = '!';
      const descriptions = {
        unconfigured: ['Not ready · unconfigured', 'Configure the relay in CPA plugin settings. No configured role was reported.'],
        disabled: ['Not ready · disabled', 'The relay was disabled in CPA plugin settings at this check.'],
        settings_invalid: ['Not ready · invalid settings', 'Correct the relay settings in CPA plugin settings. Admission was closed at this check.'],
        settings_migration_required: ['Not ready · settings migration required', 'Update the relay settings to the current schema. Admission was closed at this check.'],
        snapshot_stale: ['Not ready · snapshot stale', 'The snapshot exceeded its freshness window. Admission was closed at this check.'],
        credential_expired: ['Not ready · credential expired', 'A credential reached its expiry safety limit. Admission was closed at this check.'],
        starting: ['Not ready · awaiting sync', 'No live snapshot has synchronized successfully. Cached credentials do not authorize startup.'],
        models_pending: ['Not ready · check pending', `${data.synchronized_accounts} accounts are synchronized. Required runtime or model checks had not passed.`],
        no_available_accounts: ['Not ready · no candidates', `${data.synchronized_accounts} accounts are synchronized, but none qualified as runtime candidates. Check CPA account state and fresh credentials.`]
      };
      [title, reason] = descriptions[data.reason] || ['Not ready at last check', 'Relay admission was closed at this check. Inspect the safe reason code in diagnostic details.'];
    }
    return {age, exporter, leaseElapsed, historical, unknown, title, reason, tone, symbol};
  }
  function updateObservation() {
    if (!key) return;
    const v = view();
    put('readiness-title', v.title); put('reason', v.reason); put('state-symbol', v.symbol);
    $('readiness').dataset.tone = v.tone;
    put('observed-label', v.age === null ? 'No successful status check' : v.age < 1 ? 'Observed just now' : 'Observed ' + duration(v.age) + ' ago');
    put('observed-time', observedAt ? exact(observedAt) : '');
    put('available-label', v.exporter ? 'Receiver receipt' : data?.role !== 'receiver' ? 'Runtime candidates' : v.historical ? 'Candidates at last check' : 'Runtime candidates');
    put('inventory-context', v.exporter ? 'Latest emitted snapshot' : data?.role !== 'receiver' ? 'No configured role reported' : v.historical ? 'Last observed inventory' : 'Latest synchronized inventory');
    put('accounts-note', data?.role !== 'receiver' && !v.exporter ? 'No role-specific inventory observation was reported.' : v.exporter ? 'Exported accounts are from the latest emitted snapshot. Receipt, receiver availability, and provider inference are not verified.' : v.historical ? 'Historical counts only. Current runtime availability is unknown until a successful status check. Provider inference and quota are not verified.' : 'Runtime candidates require identity and model registration checks. Provider inference and quota are not verified.');
    const elapsed = data ? Math.max(0, (performance.now() - observedMono) / 1000) : 0;
    const snapshotAge = data?.snapshot_age_seconds === undefined ? null : data.snapshot_age_seconds + elapsed;
    const remaining = data?.fresh_until ? (Date.parse(data.fresh_until) - Date.now()) / 1000 : null;
    put('snapshot-age', snapshotAge === null ? 'Not observed' : duration(snapshotAge));
    put('remaining', remaining === null ? 'Not observed' : remaining <= 0 ? 'Deadline elapsed' : duration(remaining));
    let leaseText = 'Runtime admission checks repeat independently. Provider inference is not tested.';
    if (data?.model_check_valid_until) leaseText = v.leaseElapsed ? 'The observed runtime lease has elapsed. Checks may have renewed independently; current admission needs a new status read.' : 'The observed runtime lease has not elapsed by this browser’s clock. Checks repeat independently; admission can change before the next status read.';
    if (data?.model_check_valid_until && !data.ready) leaseText += ' A retained lease deadline does not override the last admission result.';
    put('check-explanation', v.exporter ? 'Export includes eligible physical Codex credentials, including future additions. Disabled, expired, and runtime-only credentials are excluded. A successful export does not confirm receiver ingestion.' : leaseText);
    let notice = failure ? failure + (data ? ' Showing the last successful observation.' : ' No successful status observation.') : '';
    if (paused) notice += ' Automatic status updates paused. Relay synchronization continues independently.';
    else if (document.hidden) notice += ' Automatic status updates paused while this tab is hidden.';
    if (remaining !== null && remaining <= 0) notice += ' The observed snapshot deadline has elapsed by this browser’s clock. Read status for the current admission result.';
    put('notice', notice.trim()); $('notice').hidden = !notice;
    put('refresh-status', pending ? 'Reading management status…' : paused ? 'Updates paused' : document.hidden ? 'Updates paused while hidden' : 'Automatic status checks every 5s');
    put('clock', exact(Date.now()));
    const semantic = v.unknown ? 'unknown' : [data.role, data.ready, data.reason, data.synchronized_accounts, data.available_accounts, data.last_error || '', data.last_error_at || ''].join(':');
    if (semantic !== lastSemantic) {
      lastSemantic = semantic;
      announce(v.title + '. ' + v.reason);
    }
    const pausedLease = paused && v.leaseElapsed && !v.unknown;
    if (pausedLease && !lastPausedLease) announce('The observed runtime lease has elapsed. Current admission needs a new status read.');
    lastPausedLease = pausedLease;
  }
  function render() {
    const exp = data?.role === 'exporter';
    put('role', data?.role === 'receiver' ? 'Receiver' : exp ? 'Exporter' : 'Management status');
    put('accounts-title', exp ? 'Exporter scope' : data?.role === 'receiver' ? 'Receiver accounts' : 'Relay accounts');
    put('synchronized', data ? exp ? data.accounts : data.synchronized_accounts : '—');
    put('available', data?.role === 'receiver' ? data.available_accounts : '—');
    put('synchronized-label', exp ? 'Last exported' : data?.role === 'receiver' ? 'Synchronized' : 'Reported accounts');
    put('activity-title', exp ? 'Export activity' : data?.role === 'receiver' ? 'Sync and runtime checks' : 'Relay activity');
    put('last-sync-label', exp ? 'Last emitted snapshot' : 'Last successful sync');
    put('last-attempt-label', exp ? 'Last export attempt' : 'Last sync attempt');
    $('runtime-details').hidden = data?.role !== 'receiver';
    put('freshness-explanation', exp ? 'Freshness of the last emitted snapshot. The receiver applies its own freshness and runtime admission checks.' : 'The snapshot window ends at the earlier age limit or credential expiry with safety margin. Runtime checks can close admission sooner.');
    stamp('generated', data?.generated_at); stamp('fresh-until', data?.fresh_until);
    stamp('last-sync', data?.last_sync_at, exp ? 'Emitted snapshot; receipt is not verified.' : data?.last_sync_at ? 'Fully installed and audited.' : 'No successful live synchronization observed.');
    put('last-attempt', data?.last_attempt || 'Not observed');
    const attemptNote = document.createElement('small'); attemptNote.textContent = 'Attempt timestamp not reported.'; $('last-attempt').append(attemptNote);
    put('last-error', data?.last_error || 'None reported');
    if (data?.last_error) {
      const note = document.createElement('small');
      note.textContent = exact(data.last_error_at) + ' · Recorded event; current admission is shown above.';
      $('last-error').append(note);
    }
    stamp('check-started', data?.model_check_started_at); stamp('check-finished', data?.model_check_completed_at);
    put('check-duration', data?.model_check_duration_ms === undefined ? 'Not observed' : data.model_check_duration_ms + ' ms');
    stamp('check-until', data?.model_check_valid_until);
    put('safe-codes', 'state: ' + (data?.state || 'unknown') + '\nreason: ' + (data?.reason || 'unknown') + '\nlast_attempt: ' + (data?.last_attempt || 'not_observed'));
    put('remediation', exp ? 'Exporter readiness only confirms configuration. Validate snapshots through an authenticated receiver.' : data?.ready ? 'Historical errors remain recorded. Readiness does not establish fetch recovery.' : 'Check CPA account state, credential freshness, and runtime registration. Synchronization may succeed while all runtime candidates are unavailable.');
    updateObservation();
  }
  function stopPoll() { clearTimeout(pollTimer); pollTimer = null; }
  function schedule() {
    stopPoll();
    if (key && !paused && !document.hidden) pollTimer = setTimeout(() => refresh(false), PERIOD);
  }
  function clearSession(message = '', focus = false) {
    generation++;
    stopPoll(); clearInterval(clockTimer); clockTimer = null;
    if (pending) { clearTimeout(pending.timeout); pending.controller.abort(); pending = null; }
    key = ''; data = null; observedAt = 0; observedMono = 0;
    failure = ''; paused = false; lastSemantic = ''; lastPausedLease = false;
    $('management-key').value = '';
    for (const node of document.querySelectorAll('[data-value]')) node.replaceChildren();
    $('announcement').replaceChildren();
    $('readiness').dataset.tone = 'neutral';
    for (const id of ['runtime-details', 'diagnostics']) $(id).open = false;
    $('signed-in').hidden = true; $('toolbar').hidden = true; $('login').hidden = false;
    $('notice').hidden = true;
    $('pause').setAttribute('aria-pressed', 'false'); put('pause', 'Pause updates');
    $('refresh').setAttribute('aria-disabled', 'false'); put('refresh', 'Refresh status');
    put('login-error', message); $('login-error').hidden = !message;
    if (focus) $('management-key').focus();
  }
  async function readBody(response, request) {
    if (!/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get('content-type') || '') || Number(response.headers.get('content-length')) > MAX_BODY || !response.body) throw new Error();
    const reader = response.body.getReader(), chunks = [];
    let size = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > MAX_BODY) { request.controller.abort(); throw new Error(); }
        chunks.push(part.value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return validate(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)));
  }
  async function refresh(manual = false) {
    if (!key || pending) return;
    stopPoll();
    const request = {generation, controller: new AbortController(), timeout: null, timedOut: false};
    pending = request;
    request.timeout = setTimeout(() => { request.timedOut = true; request.controller.abort(); }, TIMEOUT);
    $('refresh').setAttribute('aria-disabled', 'true'); put('refresh', 'Reading status…'); updateObservation();
    try {
      const response = await fetch(new URL('/v0/management/cpa-relay/status', location.origin), {
        method: 'GET', headers: {'Authorization': 'Bearer ' + key, 'Accept': 'application/json'},
        mode: 'same-origin', credentials: 'omit', cache: 'no-store', redirect: 'error',
        referrerPolicy: 'no-referrer', signal: request.controller.signal
      });
      if (request.generation !== generation || pending !== request) return;
      if (response.status === 401 || response.status === 403) {
        clearSession('Management authentication failed (' + response.status + '). Checks stopped. Verify the CPA management key before retrying.', true);
        return;
      }
      if (!response.ok || response.redirected) throw new Error();
      const next = await readBody(response, request);
      if (request.timedOut || request.controller.signal.aborted) throw new Error();
      if (request.generation !== generation || pending !== request) return;
      const recovered = !!failure;
      failure = ''; data = next; observedAt = Date.now(); observedMono = performance.now();
      render();
      if (manual || recovered) announce('Management status updated. ' + view().title, manual);
    } catch {
      if (request.generation !== generation || pending !== request) return;
      const nextFailure = request.timedOut ? 'Management status request timed out.' : 'Management status could not be read.';
      const changed = failure !== nextFailure;
      failure = nextFailure; updateObservation();
      if (manual || changed) announce(nextFailure + ' Refresh status to try again.', manual);
    } finally {
      clearTimeout(request.timeout);
      if (request.generation === generation && pending === request) {
        request.controller.abort(); pending = null;
        $('refresh').setAttribute('aria-disabled', 'false'); put('refresh', 'Refresh status');
        updateObservation(); schedule();
      }
    }
  }
  $('login-form').addEventListener('submit', event => {
    event.preventDefault();
    const entered = $('management-key').value;
    $('management-key').value = '';
    if (!entered.trim() || key) return;
    clearSession();
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
    if (location.protocol !== 'https:' && !(location.protocol === 'http:' && loopback)) {
      put('login-error', 'Use HTTPS to connect to management status.'); $('login-error').hidden = false; return;
    }
    if (entered.length > 4096 || /[^\x20-\x7e]/.test(entered)) {
      put('login-error', 'Enter a valid CPA management key.'); $('login-error').hidden = false; return;
    }
    key = entered;
    $('login').hidden = true; $('signed-in').hidden = false; $('toolbar').hidden = false;
    render(); $('refresh').focus();
    clockTimer = setInterval(updateObservation, 1000);
    refresh(true);
  });
  $('disconnect').addEventListener('click', () => {
    clearSession('', true); announce('Disconnected. Management key and private status cleared.');
  });
  $('refresh').addEventListener('click', () => refresh(true));
  $('pause').addEventListener('click', () => {
    paused = !paused;
    $('pause').setAttribute('aria-pressed', String(paused)); put('pause', paused ? 'Resume updates' : 'Pause updates');
    stopPoll(); updateObservation(); announce(paused ? 'Automatic status updates paused.' : 'Automatic status updates resumed.');
    if (!paused && !document.hidden) refresh(false);
  });
  $('theme').addEventListener('change', event => { document.documentElement.dataset.theme = event.target.value === 'dark' ? 'dark' : 'light'; });
  document.addEventListener('visibilitychange', () => {
    stopPoll();
    if (key && !paused && !document.hidden) refresh(false);
    updateObservation();
  });
  window.addEventListener('pagehide', () => clearSession());
  clearSession();
})();
