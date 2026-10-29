"""Conservative preconditions until a stopped-peer accounting receipt exists.

Neither enabled=False nor a successful SSH scrape proves that a peer can no
longer transfer traffic. Keep its owner and baselines even for unlimited users.
"""
from peer_lifecycle_lock import serialize_peer_lifecycle
import functools


FINALIZATION_MESSAGE = (
    "This connection can't be removed right now because its usage accounting "
    'is still being finalized. Please contact your administrator.'
)


class TrafficFinalizationRequired(RuntimeError):
    code = 'traffic_finalization_required'

    def __init__(self):
        super().__init__(FINALIZATION_MESSAGE)


def _protocol_scope(protocol):
    """Match the container actually selected by the protocol managers.

    Their first-instance and invalid suffix aliases must not bypass a guard;
    the WireGuard manager always selects its single container.
    """
    parts = str(protocol or 'awg').split('__', 1)
    base = parts[0]
    multi = {'awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'socks5'}
    single = {'wireguard', 'dns', 'adguard', 'nginx', 'exit'}
    if base not in multi | single:
        base = 'awg'  # Matches the manager dispatcher's AWG fallback.
    try:
        index = max(1, int(parts[1])) if len(parts) == 2 and base in multi else 1
    except ValueError:
        index = 1
    return base, index


def require_unowned(data, *, server_id=None, protocol=None, client_id=None,
                    user_ids=None, include_archived=False):
    """Reject a destructive scope containing any accounting ownership record.

    Match the exact protocol instance, not its base name. A dangling user ID is
    still ownership: deleting a user elsewhere is not finalization evidence.
    """
    connections = list(data.get('user_connections', []))
    if include_archived:
        for recovery in data.get('accounting_recoveries', []):
            conn = dict(recovery['connection'])
            uid = recovery['scope']['server_uid']
            conn['server_id'] = next((i for i, s in enumerate(data.get('servers', [])) if s.get('uid') == uid), None)
            connections.append(conn)
    for conn in connections:
        if server_id is not None and conn.get('server_id') != server_id:
            continue
        if protocol is not None and _protocol_scope(conn.get('protocol')) != _protocol_scope(protocol):
            continue
        if client_id is not None and conn.get('client_id') != client_id:
            continue
        if user_ids is not None and conn.get('user_id') not in user_ids:
            continue
        raise TrafficFinalizationRequired()


def guard_user_deletions(load_data):
    """Preflight a whole mixed batch before its toggle/create phases run."""
    def decorate(function):
        @functools.wraps(function)
        async def guarded(delete_uids=None, toggle_uids=None, create_conns=None):
            if delete_uids:
                require_unowned(load_data(), user_ids=set(delete_uids))
            return await function(delete_uids, toggle_uids, create_conns)
        return guarded
    return decorate
