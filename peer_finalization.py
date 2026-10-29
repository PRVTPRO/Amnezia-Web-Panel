"""Admin-only peer finalization before destructive unlink or removal.

A linked peer must not be removed without committing its last observable
bytes.  This module provides the primitives; endpoints in app.py own the
DATA_LOCK/SSH orchestration so SSH is never held across the lock.
"""
import copy
import time
import uuid
from datetime import datetime

from peer_accounting import _protocol_scope
from peer_recovery import RecoveryStore, digest
from user_state import apply_traffic_samples, traffic_server_identity


class FinalizationError(RuntimeError):
    def __init__(self, code, message, can_force=False):
        super().__init__(message)
        self.code = code
        self.can_force = can_force


def _manager_call(manager, method, protocol, *args, **kwargs):
    """WireGuard manager methods don't take a protocol argument."""
    from managers.wireguard_manager import WireGuardManager
    fn = getattr(manager, method)
    if isinstance(manager, WireGuardManager):
        return fn(*args, **kwargs)
    return fn(protocol, *args, **kwargs)


def find_connection(data, server_id, protocol, client_id, user_id=None):
    """Return the single user_connection matching the exact physical scope."""
    for conn in data.get('user_connections', []):
        if conn.get('server_id') != server_id:
            continue
        if _protocol_scope(conn.get('protocol')) != _protocol_scope(protocol):
            continue
        if conn.get('client_id') != client_id:
            continue
        if user_id is not None and conn.get('user_id') != user_id:
            continue
        return conn
    return None


def connection_scope(conn, server):
    base, instance = _protocol_scope(conn.get('protocol'))
    return {
        'connection_id': conn.get('id'),
        'server_uid': server.get('uid'),
        'protocol': base,
        'instance': instance,
        'client_id': conn.get('client_id'),
    }


def read_peer_state(manager, protocol, client_id):
    """Return (observed_bytes, quiescent) for a peer.

    observed_bytes is None when the live counter could not be read.
    quiescent is True when the peer is disabled or absent from the live
    interface, i.e. it is not currently able to forward traffic.
    """
    try:
        clients = _manager_call(manager, 'get_clients', protocol)
    except Exception:
        return None, False

    if not isinstance(clients, list):
        return None, False

    for c in clients:
        if c.get('clientId') != client_id:
            continue
        ud = c.get('userData') or {}
        rx = _int_bytes(ud.get('dataReceivedBytes'))
        tx = _int_bytes(ud.get('dataSentBytes'))
        observed = rx + tx if rx is not None and tx is not None else None
        enabled = ud.get('enabled', True)
        return observed, not bool(enabled)

    # Peer not returned by get_clients: either absent from the live interface
    # or the manager/protocol is unreachable. Treat as absent (quiescent) but
    # with no observable counter.
    return None, True


def _int_bytes(value):
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str):
        try:
            v = int(value)
            return v if v >= 0 else None
        except ValueError:
            return None
    return None


def apply_final_sample(data, conn, server, observed_bytes, observed_at):
    """Commit one last counter sample against the connection baseline.

    Returns the committed delta (always >= 0).
    """
    if observed_bytes is None:
        return 0
    sample = {
        'id': conn['id'],
        'user_id': conn['user_id'],
        'protocol': conn['protocol'],
        'client_id': conn['client_id'],
        'server_identity': traffic_server_identity(server),
        'bytes': observed_bytes,
        'observed_at': observed_at,
    }
    before_total = data.get('users', [])
    user_before = None
    for u in before_total:
        if u['id'] == conn['user_id']:
            user_before = u.get('traffic_total', 0)
            break

    apply_traffic_samples(data, [sample], datetime.now())

    user_after = None
    for u in data.get('users', []):
        if u['id'] == conn['user_id']:
            user_after = u.get('traffic_total', 0)
            break

    if user_before is not None and user_after is not None:
        return max(0, user_after - user_before)
    # Fallback when user missing: compute delta directly from connection.
    previous = conn.get('last_bytes', 0)
    if isinstance(previous, int) and previous >= 0 and observed_bytes >= previous:
        return observed_bytes - previous
    return observed_bytes


def remove_connection_row(data, conn):
    """Drop the user_connections row and return whether anything changed.

    Match the full identity (id + user_id) so a physical peer linked to
    several users only loses the row of the user being unlinked.
    """
    before = len(data.get('user_connections', []))
    data['user_connections'] = [
        c for c in data.get('user_connections', [])
        if not (c.get('id') == conn.get('id')
                and c.get('user_id') == conn.get('user_id'))
    ]
    return len(data.get('user_connections', [])) < before


def build_tombstone(conn, server, operation_id, mode, observed_bytes,
                    committed_delta, quiescent):
    """Build an accounting_recoveries entry for a finalized peer."""
    scope = connection_scope(conn, server)
    return {
        'operation_id': operation_id,
        'operation': mode,
        'scope': scope,
        'connection': dict(conn),
        'observed_bytes': observed_bytes,
        'committed_delta': committed_delta,
        'counters_verified_final': False,
        'quiescent': bool(quiescent),
        'finalized_at': datetime.now().isoformat(),
    }


def finalize_connection_record(data, conn, server, observed_bytes, observed_at,
                               mode, operation_id, quiescent):
    """Apply traffic, remove the link row, append a tombstone.

    mode is one of:
      'delete_finalized'  - peer removed after reading/estimating counters
      'delete_unverified' - peer removed without a successful counter read
      'unlink_finalized'  - link removed, peer left disabled/quiescent
      'unlink_stopped'    - peer was stopped before unlinking
    """
    committed_delta = apply_final_sample(data, conn, server, observed_bytes, observed_at)
    if not remove_connection_row(data, conn):
        raise FinalizationError('connection_not_found',
                                'Connection link disappeared during finalization')
    tombstone = build_tombstone(conn, server, operation_id, mode, observed_bytes,
                                committed_delta, quiescent)
    data.setdefault('accounting_recoveries', []).append(tombstone)
    return {
        'mode': mode,
        'observed_bytes': observed_bytes,
        'committed_delta': committed_delta,
        'counters_verified_final': False,
        'quiescent': bool(quiescent),
        'tombstone_id': operation_id,
    }


def commit_finalize(data_file, operation_id, actor, kind, intent, before, after):
    """Atomic snapshot + audit + data write via RecoveryStore."""
    store = RecoveryStore(data_file)
    return store.commit(operation_id, actor, kind, intent, before, after)


def make_intent(scope, mode):
    return digest({'scope': scope, 'mode': mode, 'version': 1})


def new_operation_id():
    return uuid.uuid4().hex
