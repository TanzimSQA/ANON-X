import logging
import unittest
from unittest.mock import patch

from anonx.config_manager import BUILTIN_DEFAULTS
from anonx.ipv4_manager import IPv4Manager
from anonx.ipv6_manager import IPv6Manager
from anonx.security_manager import CommandResult


class TestIPv4AndIPv6(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("test_ip")
        self.v4 = IPv4Manager(BUILTIN_DEFAULTS, self.logger)
        self.v6 = IPv6Manager(BUILTIN_DEFAULTS, self.logger)

    def test_ipv4_protected_status(self):
        def fake_run(args, **_kwargs):
            if args[:3] == ["nft", "list", "table"]:
                if args[4] == "anonx_nat":
                    return CommandResult(0, "meta l4proto tcp redirect to :9040", "", list(args))
                return CommandResult(0, "drop", "", list(args))
            if args[0] == "ss":
                return CommandResult(0, "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port", "", list(args))
            return CommandResult(1, "", "", list(args))

        with patch("anonx.ipv4_manager.run_safe", side_effect=fake_run):
            st = self.v4.get_status()
            self.assertTrue(st.protected)

    def test_ipv6_capture_and_restore(self):
        calls = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            if args[:2] == ["sysctl", "-n"]:
                return CommandResult(0, "0", "", list(args))
            return CommandResult(0, "", "", list(args))

        with patch("anonx.ipv6_manager.run_safe", side_effect=fake_run):
            saved = self.v6.capture_sysctl_state()
            self.assertEqual(saved["net.ipv6.conf.all.disable_ipv6"], "0")
            self.assertTrue(self.v6.restore_sysctl_state(saved))
            self.assertIn(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], calls)


if __name__ == "__main__":
    unittest.main()
