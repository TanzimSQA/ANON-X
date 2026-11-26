import copy
import logging
import tempfile
import unittest
from unittest.mock import MagicMock

from anonx.config_manager import BUILTIN_DEFAULTS
from anonx.firewall_manager import FirewallManager
from anonx.ipv6_manager import IPv6Manager
from anonx.recovery_manager import RecoveryManager


class TestRecoveryManager(unittest.TestCase):
    def test_snapshot_and_selective_recovery(self):
        logger = logging.getLogger("test_rec")
        with tempfile.TemporaryDirectory() as tmp:
            cfg = copy.deepcopy(BUILTIN_DEFAULTS)
            cfg["general"]["backup_dir"] = tmp

            fw = FirewallManager(cfg, logger)
            fw.remove_owned_tables = MagicMock(return_value=True)
            v6 = IPv6Manager(cfg, logger)
            v6.capture_sysctl_state = MagicMock(return_value={"net.ipv6.conf.all.disable_ipv6": "0"})
            v6.restore_sysctl_state = MagicMock(return_value=True)

            rec = RecoveryManager(cfg, logger, fw, v6)
            snap = rec.capture_snapshot("test")
            self.assertTrue(snap["active"])
            self.assertTrue(rec.has_snapshot())

            ok, _msg = rec.recover("unit-test")
            self.assertTrue(ok)
            fw.remove_owned_tables.assert_called_once()
            v6.restore_sysctl_state.assert_called_once_with({"net.ipv6.conf.all.disable_ipv6": "0"})


if __name__ == "__main__":
    unittest.main()
