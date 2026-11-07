"""Persistent status of long IPv6 operations.

A Docker restart or a container rebuild outlives one HTTP request. The panel
records the operation in a small JSON file next to data.json, so the UI can
poll it and the status survives a panel restart. A running operation found at
startup is marked `failed` with reason `interrupted`: nobody can finish it.
"""
import json
import os
import threading
import time
import uuid

MAX_OPERATIONS = 100


class OperationStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def _read(self):
        try:
            with open(self.path, encoding='utf-8') as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data):
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
        os.replace(tmp, self.path)

    def create(self, server_uid, kind, proto=None):
        now = time.time()
        operation = {
            'id': uuid.uuid4().hex,
            'server_uid': server_uid,
            'kind': kind,
            'proto': proto,
            'state': 'running',
            'step': 'queued',
            'reason': None,
            'created': now,
            'updated': now,
        }
        with self._lock:
            data = self._read()
            data[operation['id']] = operation
            self._prune(data)
            self._write(data)
        return operation

    def update(self, op_id, **fields):
        with self._lock:
            data = self._read()
            operation = data.get(op_id)
            if operation is None:
                return None
            operation.update(fields)
            operation['updated'] = time.time()
            self._write(data)
            return operation

    def get(self, op_id):
        with self._lock:
            return self._read().get(op_id)

    def mark_interrupted(self):
        """Give up operations that were running when the panel died."""
        with self._lock:
            data = self._read()
            changed = False
            for operation in data.values():
                if operation.get('state') == 'running':
                    operation.update(state='failed', reason='interrupted',
                                     updated=time.time())
                    changed = True
            if changed:
                self._write(data)

    @staticmethod
    def _prune(data):
        if len(data) <= MAX_OPERATIONS:
            return
        ordered = sorted(data.values(), key=lambda op: op.get('updated', 0))
        for operation in ordered[:len(data) - MAX_OPERATIONS]:
            data.pop(operation['id'], None)