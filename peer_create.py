"""Disabled-first AWG creation. The journal owns uncertain remote outcomes.

Ordering: durable intent -> inactive remote reservation -> durable panel link
-> current access check -> activation/readback. Never compensate with removal.
Only a single panel process may drive this journal (as with DATA_LOCK).
"""
import asyncio
import copy
import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import datetime

from managers.awg_manager import generate_wg_keypair
from peer_lifecycle_lock import serialize_peer_lifecycle

logger = logging.getLogger(__name__)


class PeerCreateError(RuntimeError):
    def __init__(self, message, status_code=503, operation_id=None):
        super().__init__(message)
        self.status_code = status_code
        self.operation_id = operation_id


class CreateJournal:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()

    def read(self):
        with self.lock:
            try:
                with open(self.path(), encoding='utf-8') as file:
                    data = json.load(file)
            except FileNotFoundError:
                return {}
            if not isinstance(data, dict):
                raise ValueError('Invalid peer operation journal')
            return data

    def put(self, operation):
        with self.lock:
            data = self.read()
            data[operation['id']] = copy.deepcopy(operation)
            path = self.path()
            directory = os.path.dirname(path) or '.'
            os.makedirs(directory, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix='.peer-create-', dir=directory)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as file:
                    os.chmod(temporary, 0o600)
                    json.dump(data, file)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temporary, path)
                if os.name != 'nt':
                    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(parent)
                    finally:
                        os.close(parent)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def access_signature(user):
    return {key: copy.deepcopy(user.get(key)) for key in
            ('enabled', 'disable_reasons', 'access_revision', 'expiration_date', 'traffic_limit')}


def eligible(user):
    if not user or not user.get('enabled', True) or user.get('disable_reasons'):
        return False
    if user.get('expiration_date'):
        try:
            expiry = datetime.fromisoformat(user['expiration_date'])
            if expiry <= datetime.now(expiry.tzinfo):
                return False
        except (ValueError, TypeError):
            return False
    limit = user.get('traffic_limit', 0)
    return not limit or user.get('traffic_used', 0) < limit


class PeerCreateService:
    def __init__(self, *, path, load_data, save_data, data_lock, get_ssh,
                 get_manager, public_endpoint):
        self.journal = CreateJournal(path)
        self.load_data, self.save_data, self.data_lock = load_data, save_data, data_lock
        self.get_ssh, self.get_manager, self.public_endpoint = get_ssh, get_manager, public_endpoint
        self.tasks = {}
        self.recovery_offset = 0
        self.recovery_task = None

    def schedule_recovery(self):
        """Use the existing tick without blocking traffic/policy reconciliation."""
        if self.recovery_task is None or self.recovery_task.done():
            async def background():
                try:
                    await self.recover()
                except Exception:
                    # Journal/parser/SSH diagnostics must not expose key data
                    # or abort the unrelated accounting/background cycle.
                    logger.warning('Peer creation recovery incomplete; journal retained')
            self.recovery_task = asyncio.create_task(background())
        return self.recovery_task

    @serialize_peer_lifecycle
    async def create(self, user_id, server_id, protocol, name, operation_id=None):
        if str(protocol).split('__', 1)[0] not in ('awg', 'awg2', 'awg3', 'awg_legacy'):
            raise PeerCreateError('Protocol has no inactive-create adapter', 409)
        # Read and persist the intent before even obtaining a pooled SSH client.
        async with self.data_lock:
            data = self.load_data()
            user = next((u for u in data.get('users', []) if u['id'] == user_id), None)
            if not user:
                raise PeerCreateError('User not found', 404)
            if server_id < 0 or server_id >= len(data.get('servers', [])):
                raise PeerCreateError('Server not found', 404)
            server = data['servers'][server_id]
            if not server.get('uid'):
                raise PeerCreateError('Server identity is not initialized', 409)
            identity = [user_id, server['uid'], protocol, name]
            try:
                op_id = str(uuid.UUID(operation_id)) if operation_id else str(
                    uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(identity)))
            except (ValueError, TypeError, AttributeError):
                raise PeerCreateError('Invalid operation ID', 400) from None
            operation = self.journal.read().get(op_id)
            if operation and operation['identity'] != identity:
                raise PeerCreateError('Operation ID belongs to another request', 409)
            if not operation:
                if not eligible(user):
                    raise PeerCreateError('User access is blocked', 409)
                private, public = generate_wg_keypair()
                operation = dict(id=op_id, identity=identity, private=private, public=public,
                                 access=access_signature(user), phase='intent',
                                 endpoint=[server.get('host'), server.get('ssh_port', 22), server.get('username')])
                self.journal.put(operation)
        return await self.resume(op_id)

    async def resume(self, op_id):
        task = self.tasks.get(op_id)
        if task is None or task.done():
            task = asyncio.create_task(self._execute(op_id))
            self.tasks[op_id] = task
            def finished(done):
                if self.tasks.get(op_id) is done:
                    self.tasks.pop(op_id, None)
                # A disconnected HTTP caller must not leave an unobserved
                # exception. The durable phase remains retryable.
                if not done.cancelled():
                    done.exception()
            task.add_done_callback(finished)
        return await asyncio.shield(task)

    @serialize_peer_lifecycle
    async def recover(self, limit=4):
        pending = [op['id'] for op in self.journal.read().values()
                   if op['phase'] not in ('complete', 'blocked')]
        if not pending:
            return
        offset = self.recovery_offset % len(pending)
        batch = (pending[offset:] + pending[:offset])[:limit]
        self.recovery_offset = (offset + len(batch)) % len(pending)
        for op_id in batch:
            try:
                await self.resume(op_id)
            except PeerCreateError:
                pass  # Keep the durable obligation; no blind create/remove.

    def _context(self, operation):
        user_id, uid, protocol, name = operation['identity']
        data = self.load_data()
        matches = [(i, server) for i, server in enumerate(data.get('servers', []))
                   if server.get('uid') == uid]
        if len(matches) != 1:
            raise PeerCreateError('Server identity changed; recovery required', 409, operation['id'])
        sid, server = matches[0]
        if ([server.get('host'), server.get('ssh_port', 22), server.get('username')] != operation['endpoint']
                or protocol not in server.get('protocols', {})):
            raise PeerCreateError('Server endpoint changed; recovery required', 409, operation['id'])
        user = next((u for u in data.get('users', []) if u['id'] == user_id), None)
        return data, user, sid, server

    async def _execute(self, op_id):
        operation = self.journal.read()[op_id]
        user_id, uid, protocol, name = operation['identity']
        ssh = None
        try:
            async with self.data_lock:
                _, user, sid, server = self._context(operation)
                if not user:
                    raise PeerCreateError('User no longer exists; inactive reservation retained', 409, op_id)
            ssh = await asyncio.to_thread(self.get_ssh, server)
            await asyncio.to_thread(ssh.connect)
            manager = self.get_manager(ssh, protocol)
            host, public_port = self.public_endpoint(server, protocol)
            port = server['protocols'][protocol].get('port', '55424')
            if operation['phase'] in ('complete', 'blocked'):
                # Replaying success must not re-create or re-enable a peer
                # subsequently disabled/deleted by an administrator.
                async with self.data_lock:
                    data, _, sid, _ = self._context(operation)
                    retained = any(c.get('create_operation_id') == op_id
                                   and c.get('user_id') == user_id and c.get('server_id') == sid
                                   and c.get('protocol') == protocol
                                   and c.get('client_id') == operation['public']
                                   for c in data.get('user_connections', []))
                if operation['phase'] == 'blocked' or not retained:
                    raise PeerCreateError('Operation is blocked; no automatic activation', 409, op_id)
                config = await asyncio.to_thread(manager.get_client_config, protocol,
                    operation['public'], host, port, public_port=public_port)
                return {'status': 'success', 'operation_id': op_id,
                        'client_id': operation['public'], 'config': config}
            # Safe even if a previous call timed out after the remote rename:
            # same operation/keypair, and preparation never activates a peer.
            result = await asyncio.to_thread(manager.prepare_client, protocol, op_id, name,
                operation['private'], operation['public'], host, port, public_port=public_port)
            if result.get('client_id') != operation['public']:
                raise PeerCreateError('Prepared peer identity mismatch', 409, op_id)
            operation['phase'] = 'prepared'
            self.journal.put(operation)
            async with self.data_lock:
                data, user, sid, server = self._context(operation)
                if not user:
                    raise PeerCreateError('User no longer exists; inactive reservation retained', 409, op_id)
                links = data.setdefault('user_connections', [])
                if any((c.get('id') == op_id or c.get('create_operation_id') == op_id)
                       and (c.get('client_id') != operation['public'] or c.get('user_id') != user_id
                            or c.get('server_id') != sid or c.get('protocol') != protocol)
                       for c in links):
                    raise PeerCreateError('Connection operation ownership conflict', 409, op_id)
                owned = [c for c in links if c.get('client_id') == operation['public']
                         and c.get('server_id') == sid and c.get('protocol') == protocol]
                if owned and (len(owned) != 1 or owned[0].get('create_operation_id') != op_id
                              or owned[0].get('user_id') != user_id):
                    raise PeerCreateError('Peer ownership conflict', 409, op_id)
                if not owned:
                    links.append(dict(id=op_id, user_id=user_id, server_id=sid, protocol=protocol,
                                      client_id=operation['public'], name=name,
                                      create_operation_id=op_id, created_at=datetime.now().isoformat()))
                    self.save_data(data)
            operation['phase'] = 'activating'
            self.journal.put(operation)
            # Re-read both access intent and identity after every SSH await.
            # Ownership is durable before any possible activation.
            for _ in range(4):
                async with self.data_lock:
                    _, user, _, _ = self._context(operation)
                    allowed = eligible(user) and access_signature(user) == operation['access']
                active = await asyncio.to_thread(manager.peer_is_active, protocol, operation['public'])
                if active != allowed:
                    await asyncio.to_thread(manager.toggle_client, protocol, operation['public'], allowed)
                    if await asyncio.to_thread(manager.peer_is_active, protocol, operation['public']) != allowed:
                        raise PeerCreateError('Live peer state unconfirmed; recovery pending', 503, op_id)
                async with self.data_lock:
                    _, latest, _, _ = self._context(operation)
                    current = eligible(latest) and access_signature(latest) == operation['access']
                if current != allowed:
                    continue
                operation['phase'] = 'complete' if allowed else 'blocked'
                self.journal.put(operation)
                if not allowed:
                    raise PeerCreateError('Access changed; peer retained inactive and linked', 409, op_id)
                return {'status': 'success', 'operation_id': op_id, **result}
            # Never give up with our last activation known to be stale. If
            # SSH is unavailable, keep the linked obligation pending instead
            # of reporting success or deleting its accounting ownership.
            if await asyncio.to_thread(manager.peer_is_active, protocol, operation['public']):
                await asyncio.to_thread(manager.toggle_client, protocol, operation['public'], False)
                if await asyncio.to_thread(manager.peer_is_active, protocol, operation['public']):
                    raise PeerCreateError('Disable unconfirmed; recovery pending', 503, op_id)
            raise PeerCreateError('Access is changing; recovery pending', 503, op_id)
        except PeerCreateError:
            raise
        except Exception:
            # Never forward a manager exception containing keys or configs.
            raise PeerCreateError('Peer creation incomplete; retry the same operation', 503, op_id) from None
        finally:
            if ssh:
                try:
                    await asyncio.to_thread(ssh.disconnect)
                except Exception:
                    pass
