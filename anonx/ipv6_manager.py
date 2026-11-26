"""IPv6 leak prevention, sysctl state capture, and restoration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .security_manager import run_safe


@dataclass
class IPv6Status:
    ipv6_available: bool
    protected: bool
    egress_blocked: bool
    sysctl_disabled: bool
    details: str


class IPv6Manager:
    """Prevents IPv6 bypasses via nftables egress drop and reversible sysctl settings."""

    SYSCTL_KEYS = (
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.default.disable_ipv6",
    )

    def __init__(self, config: Dict[str, Any], logger: Any) -> None:
        self.cfg = config.get("ipv6", {})
        self.fw_cfg = config.get("firewall", {})
        self.logger = logger
        self.filter_table = str(self.fw_cfg.get("table_name", "anonx_filter"))
        self.disable_sysctl = bool(self.cfg.get("disable_sysctl_ipv6", True))

    def capture_sysctl_state(self) -> Dict[str, str]:
        """Capture current IPv6 sysctl values before modification."""
        state: Dict[str, str] = {}
        for key in self.SYSCTL_KEYS:
            res = run_safe(["sysctl", "-n", key])
            if res.ok and res.stdout in ("0", "1"):
                state[key] = res.stdout.strip()
        return state

    def apply_sysctl_protection(self) -> bool:
        """Disable IPv6 via sysctl when configured, complementing nftables drop."""
        if not self.disable_sysctl:
            return True
        ok_all = True
        for key in self.SYSCTL_KEYS:
            res = run_safe(["sysctl", "-w", f"{key}=1"])
            if not res.ok:
                self.logger.warning("IPV6: Could not set %s=1: %s", key, res.stderr)
                ok_all = False
        if ok_all:
            self.logger.info("IPV6: Disabled IPv6 stack via sysctl")
        return ok_all

    def restore_sysctl_state(self, saved_state: Dict[str, str]) -> bool:
        """Restore previously captured IPv6 sysctl values."""
        if not saved_state:
            return True
        ok_all = True
        for key, val in saved_state.items():
            if key in self.SYSCTL_KEYS and val in ("0", "1"):
                res = run_safe(["sysctl", "-w", f"{key}={val}"])
                if not res.ok:
                    self.logger.warning("IPV6: Could not restore %s=%s: %s", key, val, res.stderr)
                    ok_all = False
        if ok_all:
            self.logger.info("IPV6: Restored original sysctl IPv6 configuration")
        return ok_all

    def is_ipv6_egress_blocked(self) -> bool:
        res = run_safe(["nft", "list", "table", "inet", self.filter_table])
        return res.ok and "meta nfproto ipv6 drop" in res.stdout

    def get_status(self) -> IPv6Status:
        state = self.capture_sysctl_state()
        sysctl_off = state.get("net.ipv6.conf.all.disable_ipv6") == "1"
        egress_blocked = self.is_ipv6_egress_blocked()
        protected = egress_blocked
        details = (
            "IPv6 egress and DNS blocked in nftables"
            + (" (+ sysctl disabled)" if sysctl_off else "")
            if protected
            else "IPv6 egress blocking is not active in nftables."
        )
        return IPv6Status(
            ipv6_available=not sysctl_off,
            protected=protected,
            egress_blocked=egress_blocked,
            sysctl_disabled=sysctl_off,
            details=details,
        )
