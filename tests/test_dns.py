import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from anonx.config_manager import BUILTIN_DEFAULTS
from anonx.dns_manager import DNSManager
from anonx.security_manager import CommandResult


class TestDNSManager(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("test_dns")
        self.dns = DNSManager(BUILTIN_DEFAULTS, self.logger)

    def test_read_nameservers_preserves_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "resolv.conf"
            original = "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
            p.write_text(original, encoding="utf-8")
            servers = self.dns.read_nameservers(p)
            self.assertEqual(servers, ["1.1.1.1", "8.8.8.8"])
            self.assertEqual(p.read_text(encoding="utf-8"), original)

    def test_dns_interception_check_requires_nft_rules(self):
        def fake_run(args, **_kwargs):
            if args[:3] == ["nft", "list", "table"]:
                if args[4] == "anonx_nat":
                    return CommandResult(0, "udp dport 53 redirect to :5353", "", list(args))
                return CommandResult(0, "meta nfproto ipv6 drop", "", list(args))
            return CommandResult(1, "", "", list(args))

        with patch("anonx.dns_manager.run_safe", side_effect=fake_run):
            self.assertTrue(self.dns.is_dns_interception_active())


if __name__ == "__main__":
    unittest.main()
