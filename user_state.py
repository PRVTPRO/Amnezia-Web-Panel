"""Account policy derived from current data, independently of SSH completion."""
from datetime import datetime, timedelta


def _date(value, now):
    result = datetime.fromisoformat(value)
    if now.tzinfo is None and result.tzinfo is not None:
        result = result.astimezone().replace(tzinfo=None)
    elif now.tzinfo is not None and result.tzinfo is None:
        result = result.replace(tzinfo=now.tzinfo)
    return result


def reconcile_user_state(user, now, *, manual=None, external=None):
    previous = user.get('disable_reasons')
    reasons = set(previous) if isinstance(previous, list) else (
        set() if user.get('enabled', True) else {'legacy'})
    if manual is not None:
        reasons.difference_update({'manual', 'legacy'})
        if not manual:
            reasons.add('manual')
    if external is not None:
        reasons.discard('external')
        if not external:
            reasons.add('external')
    reasons.difference_update({'quota', 'expired', 'invalid_expiration'})
    limit = user.get('traffic_limit', 0)
    if limit > 0 and user.get('traffic_used', 0) >= limit:
        reasons.add('quota')
    if user.get('expiration_date'):
        try:
            if _date(user['expiration_date'], now) <= now:
                reasons.add('expired')
        except (ValueError, TypeError):
            reasons.add('invalid_expiration')
    enabled = not reasons
    changed = previous != sorted(reasons) or user.get('enabled', True) != enabled
    if changed or manual is not None or external is not None:
        user['access_revision'] = user.get('access_revision', 0) + 1
        if user.get('enabled', True) != enabled or manual is not None or external is not None:
            user['access_sync_pending'] = True
    user['disable_reasons'] = sorted(reasons)
    user['enabled'] = enabled
    return changed


def reset_calendar_traffic(user, now):
    strategy = user.get('traffic_reset_strategy', 'never')
    if strategy not in ('daily', 'weekly', 'monthly') or not user.get('last_reset_at'):
        return False
    try:
        last = _date(user['last_reset_at'], now)
    except (ValueError, TypeError):
        return False
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if strategy == 'weekly':
        start -= timedelta(days=now.weekday())
    elif strategy == 'monthly':
        start = start.replace(day=1)
    if last >= start:
        return False
    user['traffic_used'] = 0
    user['last_reset_at'] = start.isoformat()
    return True


def traffic_server_identity(server):
    return (server.get('uid'), server.get('host'), server.get('ssh_port', 22),
            server.get('username'))


def apply_traffic_samples(data, samples, now):
    """Commit raw counters against current baselines, never precomputed deltas."""
    users = {u['id']: u for u in data.get('users', [])}
    connections = {c['id']: c for c in data.get('user_connections', [])}
    for user in users.values():
        user.setdefault('traffic_total', user.get('traffic_used', 0))
        reset_calendar_traffic(user, now)
    for sample in samples:
        conn = connections.get(sample['id'])
        if not conn or any(conn.get(k) != sample[k] for k in ('user_id', 'protocol', 'client_id')):
            continue
        sid = conn['server_id']
        if sid < 0 or sid >= len(data['servers']):
            continue
        if traffic_server_identity(data['servers'][sid]) != tuple(sample['server_identity']):
            continue
        if sample['observed_at'] <= conn.get('traffic_observed_at', 0):
            continue
        current = sample['bytes']
        if type(current) is not int or current < 0 or sample.get('counter_valid') is False:
            continue
        epoch = sample.get('counter_epoch')
        if epoch is not None:
            # Validate the complete sample before touching either baseline.
            rx, tx = sample.get('rx_bytes'), sample.get('tx_bytes')
            if (not isinstance(epoch, str) or not epoch or len(epoch) > 128
                    or type(rx) is not int or type(tx) is not int
                    or rx < 0 or tx < 0 or current != rx + tx):
                continue
        user = users.get(conn['user_id'])
        if user is None:
            continue  # An orphan must not silently consume its accounting baseline.
        previous = conn.get('last_bytes', 0)
        previous_epoch = conn.get('traffic_counter_epoch')
        epoch_changed = epoch is not None and previous_epoch is not None and epoch != previous_epoch
        decreased = current < previous
        if epoch is not None and previous_epoch == epoch:
            decreased = decreased or any(sample[key] < conn.get('last_' + key, sample[key])
                                        for key in ('rx_bytes', 'tx_bytes'))
        delta = current if epoch_changed or decreased else current - previous
        if epoch_changed or decreased:
            # Preserve the last observed old baseline, not a fabricated final
            # counter. Bytes after that observation and before reset are unknown.
            conn['traffic_accounting_gap'] = {
                'reason': 'epoch_changed' if epoch_changed else 'counter_decreased',
                'previous_bytes': previous, 'previous_epoch': previous_epoch,
                'observed_at': sample['observed_at'],
                'counters_verified_final': False,
            }
        conn['last_bytes'] = current
        conn['traffic_observed_at'] = sample['observed_at']
        if epoch is not None:
            conn['traffic_counter_epoch'] = epoch
            conn['last_rx_bytes'], conn['last_tx_bytes'] = rx, tx
        user['traffic_total'] = user.get('traffic_total', 0) + delta
        # A scrape started before a manual reset must not undo that reset.
        try:
            after_reset = sample['observed_at'] >= _date(user['last_reset_at'], now).timestamp()
        except (KeyError, ValueError, TypeError):
            after_reset = True
        if after_reset:
            user['traffic_used'] = user.get('traffic_used', 0) + delta
    for user in users.values():
        reconcile_user_state(user, now)
