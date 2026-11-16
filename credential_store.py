"""Authenticated encryption for managed-server SSH credentials.

Only ``servers[].password`` and ``servers[].private_key`` are migrated. Protocol
keys elsewhere in panel state use different schemas and are deliberately left
alone.
"""
import base64
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FORMAT = 'amnezia-ssh-credentials-v1'
ENVELOPE_FIELD = 'ssh_credentials'
KEY_BYTES = 32
_LOCK = threading.RLock()


class CredentialError(RuntimeError):
    """Stable, non-sensitive error; never include credentials or key paths."""


def default_key_path(data_file):
    return os.environ.get('CREDENTIAL_KEY_FILE') or str(Path(str(data_file) + '.credential.key'))


def contains_plaintext_ssh_credentials(data):
    return any(
        isinstance(server, dict)
        and ('password' in server or 'private_key' in server)
        and bool(server.get('password') or server.get('private_key'))
        for server in data.get('servers', [])
    )


def _b64encode(value):
    return base64.urlsafe_b64encode(value).decode('ascii')


def _b64decode(value):
    try:
        return base64.b64decode(value.encode('ascii'), altchars=b'-_', validate=True)
    except (AttributeError, UnicodeError, ValueError):
        raise CredentialError('invalid_credential_envelope') from None


def _aad(server, revision):
    try:
        identity = {
            'format': FORMAT,
            'uid': str(server['uid']),
            'host': str(server['host']),
            'ssh_port': int(server.get('ssh_port', 22)),
            'username': str(server['username']),
            'revision': str(revision),
        }
    except (KeyError, TypeError, ValueError):
        raise CredentialError('invalid_server_identity') from None
    if not all((identity['uid'], identity['host'], identity['username'], identity['revision'])):
        raise CredentialError('invalid_server_identity')
    return json.dumps(identity, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def _atomic_private_file(path, raw):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise CredentialError('unsafe_credential_key_path')
    fd, temporary = tempfile.mkstemp(prefix='.credential-key-', dir=path.parent)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as destination:
            destination.write(raw)
            destination.flush()
            os.fsync(destination.fileno())
        try:
            os.link(temporary, path)
            os.unlink(temporary)
        except (AttributeError, NotImplementedError):
            if path.exists():
                raise FileExistsError(path)
            os.replace(temporary, path)
        if os.name != 'nt':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class CredentialStore:
    def __init__(self, key_path):
        self.key_path = Path(key_path)
        self._key = None

    def _load_key(self, create=False):
        with _LOCK:
            if self._key is not None:
                return self._key
            path = self.key_path
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise CredentialError('unsafe_credential_key_path')
                try:
                    if os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) & 0o077:
                        raise CredentialError('credential_key_permissions')
                    raw = path.read_bytes()
                except OSError:
                    raise CredentialError('credential_key_unreadable') from None
                if len(raw) != KEY_BYTES:
                    raise CredentialError('invalid_credential_key')
                self._key = raw
                return raw
            if not create:
                raise CredentialError('credential_key_missing')
            raw = os.urandom(KEY_BYTES)
            try:
                _atomic_private_file(path, raw)
            except FileExistsError:
                return self._load_key(create=False)
            except OSError:
                raise CredentialError('credential_key_write_failed') from None
            self._key = raw
            return raw

    def seal(self, server, password, private_key):
        revision = _b64encode(os.urandom(16))
        nonce = os.urandom(12)
        payload = json.dumps({
            'password': str(password or ''),
            'private_key': str(private_key or ''),
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        ciphertext = AESGCM(self._load_key(create=True)).encrypt(
            nonce, payload, _aad(server, revision))
        return {
            'format': FORMAT,
            'revision': revision,
            'nonce': _b64encode(nonce),
            'ciphertext': _b64encode(ciphertext),
            'has_password': bool(password),
            'has_private_key': bool(private_key),
        }

    def resolve(self, server):
        envelope = server.get(ENVELOPE_FIELD)
        if not envelope:
            return str(server.get('password') or ''), str(server.get('private_key') or '')
        if not isinstance(envelope, dict) or envelope.get('format') != FORMAT:
            raise CredentialError('unsupported_credential_envelope')
        try:
            revision = envelope['revision']
            nonce = _b64decode(envelope['nonce'])
            ciphertext = _b64decode(envelope['ciphertext'])
            if len(nonce) != 12:
                raise CredentialError('invalid_credential_envelope')
            raw = AESGCM(self._load_key(create=False)).decrypt(
                nonce, ciphertext, _aad(server, revision))
            payload = json.loads(raw.decode('utf-8'))
            password = payload.get('password', '')
            private_key = payload.get('private_key', '')
            if not isinstance(password, str) or not isinstance(private_key, str):
                raise CredentialError('invalid_credential_payload')
            return password, private_key
        except CredentialError:
            raise
        except (InvalidTag, KeyError, TypeError, ValueError, UnicodeError):
            raise CredentialError('credential_decryption_failed') from None

    def seal_document(self, data):
        changed = False
        servers = data.get('servers', [])
        if not isinstance(servers, list):
            raise CredentialError('invalid_server_collection')
        for server in servers:
            if not isinstance(server, dict):
                raise CredentialError('invalid_server_record')
            has_legacy_fields = 'password' in server or 'private_key' in server
            password = str(server.get('password') or '')
            private_key = str(server.get('private_key') or '')
            if server.get(ENVELOPE_FIELD):
                # Mixed records are ambiguous. Empty legacy compatibility fields
                # are harmless and removed; non-empty values fail closed.
                if password or private_key:
                    raise CredentialError('mixed_credential_formats')
                if has_legacy_fields:
                    server.pop('password', None)
                    server.pop('private_key', None)
                    changed = True
                continue
            if password or private_key:
                if not server.get('uid'):
                    server['uid'] = uuid.uuid4().hex
                server[ENVELOPE_FIELD] = self.seal(server, password, private_key)
                changed = True
            if has_legacy_fields:
                server.pop('password', None)
                server.pop('private_key', None)
                changed = True
        return changed

    def seal_bytes(self, raw, context):
        nonce = os.urandom(12)
        aad = b'amnezia-panel-state-v1\x00' + context.encode('utf-8')
        return {
            'format': 'amnezia-encrypted-state-v1',
            'nonce': _b64encode(nonce),
            'ciphertext': _b64encode(AESGCM(self._load_key(create=True)).encrypt(nonce, raw, aad)),
        }

    def open_bytes(self, envelope, context):
        try:
            if envelope.get('format') != 'amnezia-encrypted-state-v1':
                raise CredentialError('unsupported_state_envelope')
            nonce = _b64decode(envelope['nonce'])
            ciphertext = _b64decode(envelope['ciphertext'])
            aad = b'amnezia-panel-state-v1\x00' + context.encode('utf-8')
            return AESGCM(self._load_key(create=False)).decrypt(nonce, ciphertext, aad)
        except CredentialError:
            raise
        except (InvalidTag, KeyError, TypeError, ValueError, AttributeError):
            raise CredentialError('state_decryption_failed') from None

    def export_portable_document(self, data):
        portable = copy.deepcopy(data)
        for server in portable.get('servers', []):
            password, private_key = self.resolve(server)
            server.pop(ENVELOPE_FIELD, None)
            server['password'] = password
            server['private_key'] = private_key
        return portable
