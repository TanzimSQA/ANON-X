import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from anonx.cli import build_parser
from anonx.config_manager import ConfigManager, ConfigValidationError
from anonx.core import AnonXCore
from anonx.security_manager import CommandSecurityError, run_safe, validate_cidr, validate_interface_name


class TestCoreAndSecurity(unittest.TestCase):
    def test_command_allowlist_blocks_unlisted_binary(self):
        with self.assertRaises(CommandSecurityError):
            run_safe(["rm", "-rf", "/"])

    def test_interface_and_cidr_validation(self):
        self.assertEqual(validate_interface_name("eth0"), "eth0")
        with self.assertRaises(ValueError):
            validate_interface_name("eth0; rm -rf /")
        self.assertEqual(validate_cidr("192.168.1.0/24"), "192.168.1.0/24")
        with self.assertRaises(ValueError):
            validate_cidr("not-a-cidr")

    def test_config_rejects_invalid_port_and_auto_wipe(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cfg.json"
            mgr = ConfigManager(cfg_path)
            with self.assertRaises(ConfigValidationError):
                mgr.update({"tor": {"trans_port": 99999}})
            with self.assertRaises(ConfigValidationError):
                mgr.update({"hardening": {"auto_wipe_logs": True}})

    def test_fail_closed_when_tor_fails(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            cfg_path = Path(tmp) / "cfg.json"
            cfg_path.write_text(
                f'{{"general": {{"backup_dir": "{tmp.replace(chr(92), "/")}", "state_dir": "{tmp.replace(chr(92), "/")}", "log_dir": "{tmp.replace(chr(92), "/")}"}}}}',
                encoding="utf-8",
            )
            core = AnonXCore(cfg_path)
            core.firewall.apply = MagicMock()
            core.ipv6.capture_sysctl_state = MagicMock(return_value={})
            core.ipv6.apply_sysctl_protection = MagicMock(return_value=True)
            core.tor.start = MagicMock(return_value=False)

            ok, msg = core.start_protection()
            self.assertFalse(ok)
            self.assertIn("Fail-closed", msg)
            core.firewall.apply.assert_called_once_with(fail_closed_only=True)
            for h in list(core.logger.handlers):
                h.close()
                core.logger.removeHandler(h)

    def test_cli_parser_commands(self):
        parser = build_parser()
        for cmd in (["status", "--detailed"], ["boot", "enable"], ["doctor"], ["recover", "--yes"]):
            ns = parser.parse_args(cmd)
            self.assertIsNotNone(ns.command)


if __name__ == "__main__":
    unittest.main()
