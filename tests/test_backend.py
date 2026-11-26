import json
import unittest
from unittest.mock import MagicMock

from anonx.logging_manager import sanitize_log_line
from privileged.service_api import PrivilegedServiceAPI


class TestBackendAPI(unittest.TestCase):
    def test_rejects_unlisted_operation_and_bad_json(self):
        core = MagicMock()
        api = PrivilegedServiceAPI(core=core)

        res1 = json.loads(api.execute("run_arbitrary_shell", "{}"))
        self.assertFalse(res1["ok"])
        self.assertIn("not allowlisted", res1["error"])

        res2 = json.loads(api.execute("get_status", "not-json"))
        self.assertFalse(res2["ok"])
        self.assertIn("Invalid JSON", res2["error"])

    def test_log_sanitization_redacts_secrets(self):
        raw = "2026-11-26 | AUTHENTICATE 4a8f9b1c2d password=supersecret token=abc123"
        clean = sanitize_log_line(raw)
        self.assertNotIn("4a8f9b1c2d", clean)
        self.assertNotIn("supersecret", clean)
        self.assertNotIn("abc123", clean)
        self.assertIn("[REDACTED]", clean)


if __name__ == "__main__":
    unittest.main()
