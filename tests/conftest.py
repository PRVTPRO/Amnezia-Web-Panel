"""Shared test isolation.

The panel computes the WARP state path once, at import time, from the current
working directory. A test that only redirects ``DATA_FILE`` would otherwise
leave ``data.json.srv_warp_state.json`` in the checkout, and a later test that
reads the working directory (the public front, for one) would see it. Tests
that already point the store at their own temporary directory are left alone.
"""
import os
import sys

import pytest


@pytest.fixture(autouse=True)
def _isolate_warp_state(tmp_path, monkeypatch):
    panel = sys.modules.get('app')
    if panel is None:
        return
    store = getattr(panel, 'warp_state_store', None)
    runtime = getattr(panel, 'warp_runtime', None)
    if store is None or runtime is None:
        return
    path = os.path.abspath(getattr(store, 'path', '') or '')
    checkout = os.path.abspath(os.getcwd())
    if not path.startswith(checkout + os.sep):
        return
    replacement = panel.WarpStateStore(
        str(tmp_path / 'data.json.srv_warp_state.json'))
    monkeypatch.setattr(panel, 'warp_state_store', replacement)
    monkeypatch.setattr(runtime, 'state_store', replacement)
