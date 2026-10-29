"""Pure health evaluation and failover policy for exit-node links.

Kept free of SSH and asyncio so threshold / hysteresis / locking decisions
are unit-tested without a panel. ExitLinkService applies the decisions using
the existing link primitives (stable server uid, restore-on-failure switch).
"""

from datetime import datetime

DEFAULT_CHECK_INTERVAL_SECONDS = 45
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_FAILBACK_STABLE_SECONDS = 180
DEFAULT_HANDSHAKE_MAX_AGE_SECONDS = 240
DEFAULT_AUTO_FAILBACK = True
DEFAULT_PROBE_EGRESS = True
MAX_EVENTS = 50

CHECK_INTERVAL_MIN, CHECK_INTERVAL_MAX = 10, 3600
FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX = 1, 20
FAILBACK_STABLE_MIN, FAILBACK_STABLE_MAX = 30, 86400
HANDSHAKE_MAX_AGE_MIN, HANDSHAKE_MAX_AGE_MAX = 60, 900

ACTION_NOOP = 'noop'
ACTION_STAY = 'stay'
ACTION_FAILOVER = 'failover'
ACTION_FAILBACK = 'failback'

REASON_DISABLED = 'disabled'
REASON_NOT_LINKED = 'not_linked'
REASON_NOT_DUE = 'not_due'
REASON_BUSY = 'skipped_busy'
REASON_NO_TARGET = 'no_healthy_target'
REASON_THRESHOLD = 'failure_threshold'
REASON_FAILBACK_STABLE = 'primary_stable'
REASON_HANDSHAKE_STALE = 'handshake_stale'
REASON_NO_HANDSHAKE = 'no_handshake'
REASON_HANDSHAKE_ERROR = 'handshake_error'
REASON_EGRESS_LEAK = 'egress_leak'
REASON_EGRESS_UNKNOWN = 'egress_unknown'
REASON_EGRESS_ERROR = 'egress_error'
REASON_OK = 'ok'
REASON_CONTAINER_STOPPED = 'container_stopped'
REASON_EXIT_NOT_FOUND = 'exit_not_found'
REASON_SSH_ERROR = 'ssh_error'
REASON_CONTAINER_RUNNING = 'container_running'


def default_config():
    return {
        'enabled': False,
        'backup_uids': [],
        'check_interval_seconds': DEFAULT_CHECK_INTERVAL_SECONDS,
        'failure_threshold': DEFAULT_FAILURE_THRESHOLD,
        'failback_stable_seconds': DEFAULT_FAILBACK_STABLE_SECONDS,
        'handshake_max_age_seconds': DEFAULT_HANDSHAKE_MAX_AGE_SECONDS,
        'auto_failback': DEFAULT_AUTO_FAILBACK,
        'probe_egress': DEFAULT_PROBE_EGRESS,
    }


def default_state():
    return {
        'primary_uid': '',
        'active_uid': '',
        'last_check_at': None,
        'last_ok': None,
        'last_reason': None,
        'consecutive_failures': 0,
        'consecutive_successes': 0,
        'primary_healthy_since': None,
        'last_switch_at': None,
    }


def _clamp_int(value, default, lo, hi):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def _as_bool(value, default):
    if value is None:
        return default
    return bool(value)


def normalize_config(raw):
    """Coerce a stored blob into a valid config. Unknown keys are ignored."""
    src = raw if isinstance(raw, dict) else {}
    cfg = default_config()
    cfg['enabled'] = _as_bool(src.get('enabled'), False)
    backups = src.get('backup_uids') or []
    if isinstance(backups, str):
        backups = [backups]
    cfg['backup_uids'] = [uid for uid in backups if isinstance(uid, str) and uid.strip()]
    cfg['check_interval_seconds'] = _clamp_int(
        src.get('check_interval_seconds'), DEFAULT_CHECK_INTERVAL_SECONDS,
        CHECK_INTERVAL_MIN, CHECK_INTERVAL_MAX)
    cfg['failure_threshold'] = _clamp_int(
        src.get('failure_threshold'), DEFAULT_FAILURE_THRESHOLD,
        FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX)
    cfg['failback_stable_seconds'] = _clamp_int(
        src.get('failback_stable_seconds'), DEFAULT_FAILBACK_STABLE_SECONDS,
        FAILBACK_STABLE_MIN, FAILBACK_STABLE_MAX)
    cfg['handshake_max_age_seconds'] = _clamp_int(
        src.get('handshake_max_age_seconds'), DEFAULT_HANDSHAKE_MAX_AGE_SECONDS,
        HANDSHAKE_MAX_AGE_MIN, HANDSHAKE_MAX_AGE_MAX)
    cfg['auto_failback'] = _as_bool(src.get('auto_failback'), DEFAULT_AUTO_FAILBACK)
    cfg['probe_egress'] = _as_bool(src.get('probe_egress'), DEFAULT_PROBE_EGRESS)
    return cfg


def normalize_state(raw):
    src = raw if isinstance(raw, dict) else {}
    state = default_state()
    for key in state:
        if key in src:
            state[key] = src[key]
    try:
        state['consecutive_failures'] = max(0, int(state.get('consecutive_failures') or 0))
    except (TypeError, ValueError):
        state['consecutive_failures'] = 0
    try:
        state['consecutive_successes'] = max(0, int(state.get('consecutive_successes') or 0))
    except (TypeError, ValueError):
        state['consecutive_successes'] = 0
    state['primary_uid'] = (state.get('primary_uid') or '').strip()
    state['active_uid'] = (state.get('active_uid') or '').strip()
    return state


def sanitize_backup_uids(backup_uids, *, entry_uid, primary_uid, known_exit_uids):
    """Keep order, drop empties / self / primary / unknown / duplicates.

    Cross-server identity is the stable server uid (not a list index): a
    reorder or delete must not silently retarget a backup at the wrong host.
    Unknown uids are dropped (fail-closed) rather than stored for later.
    """
    known = set(known_exit_uids or [])
    seen = set()
    ordered = []
    for uid in backup_uids or []:
        if not isinstance(uid, str):
            continue
        uid = uid.strip()
        if not uid or uid in seen:
            continue
        if uid == (entry_uid or '') or uid == (primary_uid or ''):
            continue
        if uid not in known:
            continue
        seen.add(uid)
        ordered.append(uid)
    return ordered


def ordered_exit_uids(primary_uid, backup_uids):
    """Preferred exit first, then the ordered backups, unique."""
    ordered = []
    seen = set()
    for uid in [primary_uid, *(backup_uids or [])]:
        uid = (uid or '').strip()
        if not uid or uid in seen:
            continue
        seen.add(uid)
        ordered.append(uid)
    return ordered


def evaluate_active_health(*, handshake_age, handshake_error=None, status_missing=False,
                           egress=None, probe_egress=True, handshake_max_age=DEFAULT_HANDSHAKE_MAX_AGE_SECONDS):
    """Health of the *currently linked* exit, from the entry container.

    Handshake age comes from `wg/awg show exit0`; the optional egress probe
    is the existing curl-via-exit0 check. A NAT mismatch is not a failure
    (the public IP of a NATed exit need not equal endpoint_host).
    """
    if status_missing:
        return False, REASON_NO_HANDSHAKE
    if handshake_error:
        return False, REASON_HANDSHAKE_ERROR
    if handshake_age is None:
        return False, REASON_NO_HANDSHAKE
    try:
        age = int(handshake_age)
    except (TypeError, ValueError):
        return False, REASON_NO_HANDSHAKE
    if age < 0 or age > handshake_max_age:
        return False, REASON_HANDSHAKE_STALE

    if probe_egress:
        egress = egress if isinstance(egress, dict) else {}
        if egress.get('error'):
            return False, REASON_EGRESS_ERROR
        if egress.get('leaks'):
            return False, REASON_EGRESS_LEAK
        if not egress.get('via_exit'):
            return False, REASON_EGRESS_UNKNOWN
    return True, REASON_OK


def evaluate_candidate_health(*, installed=True, container_running=False, ssh_error=None):
    """Health of an exit we are *not* linked to (no tunnel handshake available)."""
    if ssh_error:
        return False, REASON_SSH_ERROR
    if not installed:
        return False, REASON_EXIT_NOT_FOUND
    if not container_running:
        return False, REASON_CONTAINER_STOPPED
    return True, REASON_CONTAINER_RUNNING


def parse_ts(value):
    """Unix timestamp from an ISO string, a number, or None."""
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return None


def isoformat(now):
    return datetime.fromtimestamp(now).isoformat()


def due_for_check(state, interval_seconds, now):
    last = parse_ts((state or {}).get('last_check_at'))
    if last is None:
        return True
    return (now - last) >= interval_seconds


def next_healthy_target(ordered_uids, active_uid, healthy_uids):
    """First healthy uid in the ordered list that is not the active exit."""
    healthy = set(healthy_uids or [])
    for uid in ordered_uids or []:
        if uid and uid != active_uid and uid in healthy:
            return uid
    return None


def decide(*, config, state, now, active_ok, active_reason, primary_ok, healthy_uids):
    """Apply counters, hysteresis and pick stay / failover / failback.

    `healthy_uids` is the set of exits the caller has probed as usable this
    tick (active if `active_ok`, plus any candidate whose container is up).
    """
    cfg = normalize_config(config)
    st = normalize_state(state)
    if not cfg['enabled']:
        return {'action': ACTION_NOOP, 'reason': REASON_DISABLED, 'target_uid': None, 'state': st}

    primary = st.get('primary_uid') or ''
    active = st.get('active_uid') or primary
    st['active_uid'] = active
    st['last_check_at'] = isoformat(now)
    st['last_ok'] = bool(active_ok)
    st['last_reason'] = active_reason

    if active_ok:
        st['consecutive_failures'] = 0
        st['consecutive_successes'] = st['consecutive_successes'] + 1
    else:
        st['consecutive_successes'] = 0
        st['consecutive_failures'] = st['consecutive_failures'] + 1

    if cfg['auto_failback'] and primary and active != primary:
        if primary_ok:
            since = parse_ts(st.get('primary_healthy_since'))
            if since is None:
                st['primary_healthy_since'] = isoformat(now)
                since = now
            if (now - since) >= cfg['failback_stable_seconds'] and primary in (healthy_uids or set()):
                return {
                    'action': ACTION_FAILBACK,
                    'reason': REASON_FAILBACK_STABLE,
                    'target_uid': primary,
                    'state': st,
                }
        else:
            st['primary_healthy_since'] = None
    else:
        if active == primary:
            st['primary_healthy_since'] = isoformat(now) if active_ok else None

    if st['consecutive_failures'] >= cfg['failure_threshold']:
        target = next_healthy_target(
            ordered_exit_uids(primary, cfg.get('backup_uids')),
            active,
            healthy_uids,
        )
        if target:
            return {
                'action': ACTION_FAILOVER,
                'reason': active_reason or REASON_THRESHOLD,
                'target_uid': target,
                'state': st,
            }
        return {
            'action': ACTION_STAY,
            'reason': REASON_NO_TARGET,
            'target_uid': None,
            'state': st,
        }

    return {'action': ACTION_STAY, 'reason': active_reason or REASON_OK, 'target_uid': None, 'state': st}


def record_switch(state, *, now, from_uid, to_uid, action, reason):
    """Reset counters after a successful switch and stamp last_switch_at."""
    st = normalize_state(state)
    st['active_uid'] = to_uid or ''
    st['consecutive_failures'] = 0
    st['consecutive_successes'] = 0
    st['last_switch_at'] = isoformat(now)
    st['last_ok'] = True
    st['last_reason'] = reason
    if action == ACTION_FAILBACK or (to_uid and to_uid == st.get('primary_uid')):
        st['primary_healthy_since'] = isoformat(now)
    return st


def append_event(events, *, now, action, from_uid, to_uid, reason, limit=MAX_EVENTS):
    """Prepend a switch event; keep the log bounded."""
    event = {
        'at': isoformat(now),
        'action': action,
        'from_uid': from_uid or '',
        'to_uid': to_uid or '',
        'reason': reason or '',
    }
    log = [event]
    for item in events or []:
        if isinstance(item, dict):
            log.append(item)
        if len(log) >= limit:
            break
    return log[:limit]
