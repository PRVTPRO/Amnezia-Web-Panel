# IPv6 feature: how to run the tests

## Two groups, two commands

The Playwright plugin starts one session event loop. Tests that call
`asyncio.run()` then fail with `RuntimeError: asyncio.run() cannot be called
from a running event loop`. So the suite runs in two groups.

### Group A: unit and API tests (no browser)

```powershell
$env:PYTHONIOENCODING='utf-8'
python -m pytest tests -q -p no:randomly -p no:playwright `
  --ignore=tests/test_playwright_e2e.py `
  --ignore=tests/test_server_card_trust_browser.py `
  --ignore=tests/test_server_wizard_browser.py `
  --ignore=tests/test_panel_backup_browser.py `
  --ignore=tests/test_server_crud_browser.py `
  --ignore=tests/test_ssh_onboarding_browser.py
```

`-p no:playwright` is required. Without it, 238 sync tests fail.

`tests/test_marketplace_dispatch.py` and `tests/test_server_clear_races.py`
import Playwright only for an optional path. They pass in this group.

### Group B: browser tests

Start the panel first. Use a temporary data file, never the production one.

```powershell
$env:DATA_FILE="$env:TEMP\awp-e2e\data.json"
python -m uvicorn app:app --port 8000 --host 127.0.0.1
```

Then run:

```powershell
$env:PYTHONIOENCODING='utf-8'
python -m pytest tests/test_server_card_trust_browser.py `
  tests/test_server_wizard_browser.py `
  tests/test_panel_backup_browser.py `
  tests/test_server_crud_browser.py `
  tests/test_ssh_onboarding_browser.py `
  tests/test_ipv6_ui_browser.py `
  tests/test_playwright_e2e.py -q -p no:randomly
```

Order matters. `test_playwright_e2e.py` must be last. It uses the plugin `page`
fixture, and the plugin keeps an asyncio loop. The other five files call
`sync_playwright().start()` themselves, and they fail inside that loop with
`Playwright Sync API cannot be used inside the asyncio loop`.

The tests use `http://127.0.0.1:8000`. They do not start the panel.

## IPv6 test files

| File | Covers |
|---|---|
| `tests/test_ipv6_manager.py` | subnet index parsing, dns6, peer counting, blocked_reason, recreate and rollback |
| `tests/test_ipv6_api.py` | 4 endpoints, permissions, HTTP status map, install gate |
| `tests/test_ipv6_api_contract.py` | cross-origin 403, Bearer/support matrix, secrets, 20 s cache, reason→status map |
| `tests/test_ipv6_status.py` | `/ip-status` states, IPv4/IPv6 filtering, `peers: null`, no SSH in the read |
| `tests/test_ipv6_operations.py` | persistent op store, pruning, `interrupted` at startup |
| `tests/test_ipv6_install_gate.py` | new instances follow the server preference and `AWG_IPV6` |
| `tests/test_ipv6_docker.py` | daemon.json merge, base64 write, recovery, refusal order |
| `tests/test_ipv6_recreate.py` | inspect-based run command, config sha check, rollback order |
| `tests/test_ipv6_hardening.py` | `Config.Env`/`Entrypoint`/`Cmd`/`Labels` and `-p` skip in the recreate command, DNS/DNS6 validation, stopped-container `can_disable`, `recreate_rollback_failed`, guarded Docker worker start, install `AWG_IPV6` override, quote escaping in `escapeHtml` |
| `tests/test_ipv6_docker_detect.py` | Docker presence probe runs as `sh -c 'command -v docker'`, so `sudo` on a non-root host does not reject the `command` builtin; the old unwrapped shape is pinned as failing |
| `tests/test_ipv6_client_config.py` | client IPv6/DNS6 derivation and generated config |
| `tests/test_ipv6_i18n.py` | 5 locales, placeholders, Cyrillic leakage, CSS tokens |
| `tests/test_ipv6_ui_browser.py` | chips, modal, repair, install note, phone, light theme, RTL |
| `tests/test_server_ipv6_header.py` | header chips come from `/ip-status` |
| `tests/test_exit_link_service.py` | `link()` refuses an IPv6 instance |

`tests/test_ipv6_hardening.py` and `tests/test_ipv6_docker_detect.py` are new
on the `feat/ipv6-ovh-test` branch and are not committed yet. They are
collected by the Group A command automatically.

## Screenshots

`design/capture_ipv6_modal.py` writes three PNG files:
dark theme, light theme, phone width. It needs the panel on port 8000 and one
server at index 0.

```powershell
python design/capture_ipv6_modal.py
```

The in-app browser screenshot tool fails when its window is not visible. Use
this script instead.

## Known external failures

`tests/test_exit_failover.py` fails on Windows with `OSError [Errno 22]` from
`datetime.fromtimestamp()`. The file is not part of this feature.