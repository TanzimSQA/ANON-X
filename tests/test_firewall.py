import copy
import logging
import unittest
from unittest.mock import patch

from anonx.config_manager import BUILTIN_DEFAULTS
from anonx.firewall_manager import FirewallManager
from anonx.security_manager import CommandResult


class TestFirewallManager(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("test_fw")
        self.fw = FirewallManager(BUILTIN_DEFAULTS, self.logger)

    def test_never_flushes_global_ruleset(self):
        ruleset = self.fw.generate_ruleset(fail_closed_only=False)
        self.assertNotIn("flush ruleset", ruleset)
        self.assertNotIn("iptables -F", ruleset)
        self.assertIn("table ip anonx_nat", ruleset)
        self.assertIn("table inet anonx_filter", ruleset)

    def test_tor_exemption_udp_drop_and_ipv6_drop(self):
        ruleset = self.fw.generate_ruleset(fail_closed_only=False)
        self.assertIn('meta skuid "debian-tor" accept', ruleset)
        self.assertIn("meta nfproto ipv6 drop", ruleset)
        self.assertIn("meta l4proto udp drop", ruleset)
        self.assertIn("udp dport 53 redirect to :5353", ruleset)
        self.assertIn("meta l4proto tcp redirect to :9040", ruleset)

    def test_fail_closed_ruleset_omits_nat_and_drops_egress(self):
        ruleset = self.fw.generate_ruleset(fail_closed_only=True)
        self.assertNotIn("redirect to :9040", ruleset)
        self.assertIn("meta nfproto ipv6 drop", ruleset)
        self.assertIn("        drop", ruleset)

    def test_lan_cidr_included_only_when_enabled(self):
        cfg = copy.deepcopy(BUILTIN_DEFAULTS)
        cfg["firewall"]["allow_lan"] = True
        fw_lan = FirewallManager(cfg, self.logger)
        ruleset = fw_lan.generate_ruleset(fail_closed_only=False)
        self.assertIn("192.168.0.0/16", ruleset)

    def test_remove_owned_tables_only_deletes_anonx(self):
        calls = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            return CommandResult(0, "", "", list(args))

        with patch("anonx.firewall_manager.run_safe", side_effect=fake_run):
            ok = self.fw.remove_owned_tables()
        self.assertTrue(ok)
        self.assertIn(["nft", "delete", "table", "ip", "anonx_nat"], calls)
        self.assertIn(["nft", "delete", "table", "inet", "anonx_filter"], calls)


if __name__ == "__main__":
    unittest.main()
