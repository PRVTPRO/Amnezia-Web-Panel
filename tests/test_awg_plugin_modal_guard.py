"""The AmneziaWG components dialog must start its probe even with no cached status.

Regression: the xray core updater (PR #338) removed the `return` from the
`if (!awgPluginStatus)` branch of `renderAwgPluginModal`.  Opening the dialog
then raised `TypeError: Cannot read properties of null (reading 'components')`
before `loadAwgPluginStatus()` was called, so the badge stayed in the loading
state and the dialog showed the error text forever.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_TEMPLATE = ROOT / "templates" / "server.html"


def _function_body(source, name, next_name):
    start = source.index("function %s(" % name)
    end = source.index("function %s(" % next_name, start)
    return source[start:end]


class TestAwgPluginModalGuard(unittest.TestCase):
    def setUp(self):
        self.template = SERVER_TEMPLATE.read_text(encoding="utf-8")

    def test_missing_status_stops_before_reading_components(self):
        body = _function_body(self.template, "renderAwgPluginModal",
                              "updateAwgPluginComponentLine")
        guard = re.search(r"if \(!awgPluginStatus\) \{(.*?)\}", body, re.S)
        self.assertIsNotNone(guard, "renderAwgPluginModal lost its null guard")
        self.assertIn(
            "return;", guard.group(1),
            "the null guard must return, otherwise the probe never starts",
        )

    def test_dialog_starts_the_probe_and_shows_a_checking_placeholder(self):
        body = _function_body(self.template, "openAwgPluginModal",
                              "closeAwgPluginModal")
        self.assertIn("loadAwgPluginStatus(true)", body)
        self.assertIn("awgPluginLoading = true", body)
        self.assertIn("labels.loading", self.template)


if __name__ == "__main__":
    unittest.main()
