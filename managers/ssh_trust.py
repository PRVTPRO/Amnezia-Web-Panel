"""Fail-closed SSH trust enrollment. Probes perform key exchange, never auth."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import sys
import tempfile
import threading
import time

import paramiko

LOCK = threading.RLock()
_SECRET = secrets.token_bytes(32)
_DATA_FILE = None


def configure(data_file):
    global _DATA_FILE
    _DATA_FILE = data_file


def trust_path():
    default_dir = (os.path.dirname(sys.executable) if getattr(sys, 'frozen', False)
                   else os.path.dirname(os.path.dirname(__file__)))
    data = os.environ.get('DATA_FILE') or _DATA_FILE or os.path.join(default_dir, 'data.json')
    return os.path.abspath(os.path.expanduser(os.environ.get('SSH_KNOWN_HOSTS_FILE') or
                                            os.path.join(os.path.dirname(data), 'ssh_known_hosts')))


def identity(server):
    host = server.get('host', '')
    port = server.get('ssh_port', 22)
    if not isinstance(host, str) or not host or any(c.isspace() for c in host) or any(c in host for c in ',|[]'):
        raise ValueError('Invalid SSH host')
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Invalid SSH port')
    return host, port


def host_name(host, port):
    return host if port == 22 else f'[{host}]:{port}'


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def system_keys():
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    return client._system_host_keys


def panel_keys():
    keys = paramiko.HostKeys()
    if os.path.exists(trust_path()):
        keys.load(trust_path())
    return keys


def probe(host, port):
    # No username, password, private key, SSH agent or auth method enters here.
    with socket.create_connection((host, port), timeout=10) as sock:
        transport = paramiko.Transport(sock)
        try:
            # Match SSHClient.connect: system pins take precedence, and its
            # first stored key type is moved to the front of the KEX offers.
            name = host_name(host, port)
            with LOCK:
                effective = system_keys().lookup(name) or panel_keys().lookup(name)
                if effective:
                    preferred = next(iter(effective))
                    options = transport.get_security_options()
                    options.key_types = [preferred] + [k for k in options.key_types if k != preferred]
            transport.start_client(timeout=10)
            return transport.get_remote_server_key()
        finally:
            transport.close()


def _token(payload):
    body = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
    return body + '.' + hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()


def _trust_snapshot(name):
    return [[[k.get_name(), k.get_base64()] for k in (source.lookup(name) or {}).values()]
            for source in (system_keys(), panel_keys())]


def saved_status(server):
    """Report saved pin presence without network I/O (not live verification)."""
    host, port = identity(server)
    name = host_name(host, port)
    with LOCK:
        return 'trusted' if system_keys().lookup(name) or panel_keys().lookup(name) else 'unknown'


def inspect(server):
    host, port = identity(server)
    key = probe(host, port)
    name = host_name(host, port)
    with LOCK:
        system, local = system_keys().lookup(name), panel_keys().lookup(name)
        effective = system or local
        old = [{'algorithm': k.get_name(), 'fingerprint': fingerprint(k)}
               for source in (system, local) if source for k in source.values()]
        status = 'unknown' if not effective else ('trusted' if effective.get(key.get_name()) == key else 'changed')
        result = {'host': host, 'port': port, 'algorithm': key.get_name(),
                  'fingerprint': fingerprint(key), 'old_fingerprints': old, 'status': status}
        result['token'] = _token({'host': host, 'port': port, 'uid': server.get('uid'),
                                  'key': key.get_base64(), 'algorithm': key.get_name(),
                                  'trust': _trust_snapshot(name),
                                  'expires': time.time() + 300})
        return result


def enroll(server, token, validate_endpoint=None):
    host, port = identity(server)
    try:
        body, signature = token.split('.')
        expected = hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(body))
        if (payload['expires'] < time.time() or payload['host'] != host or
                payload['port'] != port or payload['uid'] != server.get('uid')):
            raise ValueError()
    except Exception as exc:
        raise ValueError('Invalid or expired SSH confirmation; inspect again') from exc
    key = probe(host, port)
    if key.get_base64() != payload['key'] or key.get_name() != payload['algorithm']:
        raise ValueError('SSH candidate changed; inspect and verify again')
    name = host_name(host, port)
    with LOCK:
        if validate_endpoint is not None and not validate_endpoint():
            raise ValueError('Server endpoint changed; probe again')
        system = system_keys().lookup(name)
        if system and system.get(key.get_name()) != key:
            raise ValueError('Conflicting system known_hosts entry; administrator must correct it independently first')
        if payload.get('trust') != _trust_snapshot(name):
            raise ValueError('Trust changed; probe again')
        path = trust_path()
        if os.path.exists(path) and not os.stat(path).st_mode & stat.S_IWRITE:
            raise PermissionError('SSH trust file is read-only')
        keys = panel_keys()
        # Remove all entries for this endpoint, including hashed names and old
        # algorithms, preserving aliases on shared lines and unrelated hosts.
        for entry in list(keys._entries):
            entry.hostnames = [h for h in entry.hostnames
                               if not keys._hostname_matches(name, paramiko.hostkeys.HostKeyEntry([h], entry.key))]
        keys._entries = [entry for entry in keys._entries if entry.hostnames]
        keys.add(name, key.get_name(), key)
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.ssh-trust-', dir=directory)
        os.close(fd)
        try:
            os.chmod(temporary, 0o600)
            keys.save(temporary)
            with open(temporary, 'rb+') as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return {'status': 'success'}
