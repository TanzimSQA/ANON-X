import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from anonx.config_manager import BUILTIN_DEFAULTS
from anonx.tor_manager import TorManager


class TestTorManager(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("test_tor")
        self.tor = TorManager(BUILTIN_DEFAULTS, self.logger)

    def test_dropin_config_enforces_local_cookie_auth(self):
        cfg = self.tor.render_dropin_config()
        self.assertIn("TransPort 127.0.0.1:9040", cfg)
        self.assertIn("DNSPort 127.0.0.1:5353", cfg)
        self.assertIn("ControlPort 127.0.0.1:9051", cfg)
        self.assertIn("CookieAuthentication 1", cfg)
        self.assertNotIn("0.0.0.0:9051", cfg)

    def test_bootstrap_parsing(self):
        with patch.object(self.tor, "_control_command", return_value=['250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\n250 OK']):
            pct, summary = self.tor.get_bootstrap_status()
            self.assertEqual(pct, 100)
            self.assertEqual(summary, "Done")

    def test_new_identity_success(self):
        with patch.object(self.tor, "_control_command", return_value=["250 OK"]):
            ok, msg = self.tor.request_new_identity()
            self.assertTrue(ok)
            self.assertIn("does not guarantee", msg)


if __name__ == "__main__":
    unittest.main()
