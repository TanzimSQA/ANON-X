import copy
import logging
import tempfile
import unittest
from unittest.mock import patch

from anonx.config_manager import BUILTIN_DEFAULTS
from anonx.security_manager import CommandResult
from anonx.startup_manager import StartupManager


class TestStartupManager(unittest.TestCase):
    def test_boot_enable_and_status(self):
        logger = logging.getLogger("test_boot")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = copy.deepcopy(BUILTIN_DEFAULTS)
            cfg["general"]["state_dir"] = tmp
            mgr = StartupManager(cfg, logger)
            mgr.record_boot_verification(True, "Verified")

            with patch("anonx.startup_manager.run_safe", return_value=CommandResult(0, "enabled", "", [])):
                ok, _ = mgr.enable_boot()
                self.assertTrue(ok)
                st = mgr.get_status()
                self.assertTrue(st.boot_protection_enabled)
                self.assertEqual(st.last_boot_result, "PASS")


if __name__ == "__main__":
    unittest.main()
