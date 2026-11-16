"""Tests for Telegram Mini App initData signature validation."""
import ast
import hashlib
import hmac
import json
from pathlib import Path
import re
import time
import unittest
import urllib.parse


APP_SOURCE = Path(__file__).resolve().parents[1] / "app.py"
_TREE = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
_HELPER = next(
    node for node in _TREE.body
    if isinstance(node, ast.FunctionDef)
    and node.name == "_verify_telegram_webapp_init_data"
)
_NAMESPACE = {
    "Optional": __import__("typing").Optional,
    "urllib": urllib,
    "json": json,
    "re": re,
    "time": time,
    "hmac": hmac,
    "hashlib": hashlib,
}
exec(compile(ast.Module(body=[_HELPER], type_ignores=[]), str(APP_SOURCE), "exec"), _NAMESPACE)
verify_init_data = _NAMESPACE["_verify_telegram_webapp_init_data"]


def make_init_data(bot_token, user_id=123456, auth_date=None):
    auth_date = int(time.time()) if auth_date is None else auth_date
    values = {
        "auth_date": str(auth_date),
        "query_id": "AAE-test",
        "user": json.dumps({"id": user_id, "first_name": "Test"}, separators=(",", ":")),
    }
    check_string = "\n".join(f"{key}={values[key]}" for key in sorted(values))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    values["hash"] = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(values)


class TelegramWebAppInitDataTests(unittest.TestCase):
    def test_accepts_valid_init_data(self):
        now = 1_800_000_000
        init_data = make_init_data("123:bot-token", auth_date=now)
        user = verify_init_data(init_data, "123:bot-token", now=now)
        self.assertEqual(user["id"], 123456)
        self.assertEqual(user["first_name"], "Test")

    def test_rejects_tampered_data(self):
        now = 1_800_000_000
        init_data = make_init_data("123:bot-token", auth_date=now)
        init_data = init_data.replace("Test", "Evil")
        with self.assertRaises(ValueError):
            verify_init_data(init_data, "123:bot-token", now=now)

    def test_rejects_expired_data(self):
        now = 1_800_000_000
        init_data = make_init_data("123:bot-token", auth_date=now - 86401)
        with self.assertRaisesRegex(ValueError, "expired_init_data"):
            verify_init_data(init_data, "123:bot-token", now=now)

    def test_rejects_duplicate_fields(self):
        now = 1_800_000_000
        init_data = make_init_data("123:bot-token", auth_date=now) + "&auth_date=" + str(now)
        with self.assertRaises(ValueError):
            verify_init_data(init_data, "123:bot-token", now=now)


if __name__ == "__main__":
    unittest.main()
