"""Unified ANON-X backend orchestrator shared by CLI, daemon, D-Bus, and GUI."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any, Dict, List

from . import __version__
from .config_manager import ConfigManager
from .diagnostics import DiagnosticsEngine
from .dns_manager import DNSManager
from .firewall_manager import FirewallError, FirewallManager
from .ipv4_manager import IPv4Manager
from .ipv6_manager import IPv6Manager
from .logging_manager import LoggingManager
from .network_manager import NetworkEnvironmentManager
from .recovery_manager import RecoveryManager
from .security_manager import SecurityManager
from .startup_manager import StartupManager
from .tor_manager import TorManager


def detect_kali_version() -> str:
    os_release = Path("/etc/os-release")
    if os_release.exists():
        for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return f"{platform.system()} {platform.release()}"


class AnonXCore:
    """Single source of truth for all ANON-X privacy operations."""

    def __init__(self, config_path: Path | str | None = None) -> None:
        self.config_mgr = ConfigManager(config_path)
        cfg = self.config_mgr.data
        log_dir = cfg.get("general", {}).get("log_dir", "/var/log/anonx")
        log_level = cfg.get("general", {}).get("log_level", "INFO")
        self.log_mgr = LoggingManager(log_dir=log_dir, level=log_level)
        self.logger = self.log_mgr.logger

        self.security = SecurityManager()
        self.tor = TorManager(cfg, self.logger)
        self.firewall = FirewallManager(cfg, self.logger)
        self.dns = DNSManager(cfg, self.logger)
        self.ipv4 = IPv4Manager(cfg, self.logger)
        self.ipv6 = IPv6Manager(cfg, self.logger)
        self.net = NetworkEnvironmentManager()
        self.startup = StartupManager(cfg, self.logger)
        self.recovery = RecoveryManager(cfg, self.logger, self.firewall, self.ipv6)
        self.diagnostics = DiagnosticsEngine(
            self.tor, self.firewall, self.dns, self.ipv4, self.ipv6,
            self.net, self.startup, self.recovery, self.security,
        )

    def _reload_managers(self) -> None:
        cfg = self.config_mgr.data
        self.tor = TorManager(cfg, self.logger)
        self.firewall = FirewallManager(cfg, self.logger)
        self.dns = DNSManager(cfg, self.logger)
        self.ipv4 = IPv4Manager(cfg, self.logger)
        self.ipv6 = IPv6Manager(cfg, self.logger)
        self.startup = StartupManager(cfg, self.logger)
        self.recovery = RecoveryManager(cfg, self.logger, self.firewall, self.ipv6)
        self.diagnostics = DiagnosticsEngine(
            self.tor, self.firewall, self.dns, self.ipv4, self.ipv6,
            self.net, self.startup, self.recovery, self.security,
        )

    def start_protection(self) -> tuple[bool, str]:
        """Activate fail-closed firewall first, start Tor, wait for bootstrap, and verify."""
        self.recovery.capture_snapshot(trigger="start")
        try:
            # Step 1: Fail-closed firewall before Tor starts (eliminates direct-connection window)
            self.firewall.apply(fail_closed_only=True)
            self.ipv6.apply_sysctl_protection()
        except FirewallError as exc:
            return False, f"Firewall initialization failed: {exc}"

        # Step 2: Start Tor
        if not self.tor.start():
            self.logger.error("CORE: Tor failed to start; retaining fail-closed firewall.")
            return False, "Tor failed to start. Fail-closed firewall remains active to prevent leaks."

        # Step 3: Wait for Tor bootstrap
        ok, pct, summary = self.tor.wait_for_bootstrap()
        if not ok:
            self.logger.error("CORE: Tor bootstrap incomplete (%d%%); retaining fail-closed firewall.", pct)
            return False, f"Tor bootstrap incomplete ({pct}%: {summary}). Fail-closed firewall remains active."

        # Step 4: Enable full transparent NAT + filter rules
        try:
            self.firewall.apply(fail_closed_only=False)
        except FirewallError as exc:
            return False, f"Transparent routing rules failed: {exc}"

        self.startup.record_boot_verification(True, "Protection active and verified")
        return True, "ANON-X privacy protection is ACTIVE and verified locally."

    def stop_protection(self) -> tuple[bool, str]:
        """Safely stop ANON-X protection and restore only ANON-X-changed settings."""
        ok, msg = self.recovery.recover(reason="stop")
        return ok, msg

    def restart_protection(self) -> tuple[bool, str]:
        self.stop_protection()
        return self.start_protection()

    def new_identity(self) -> tuple[bool, str]:
        return self.tor.request_new_identity()

    def verify(self) -> Dict[str, Any]:
        return self.diagnostics.run_all()

    def get_status(self) -> Dict[str, Any]:
        tor_st = self.tor.get_status()
        fw_st = self.firewall.get_status()
        dns_st = self.dns.get_status()
        v4_st = self.ipv4.get_status()
        v6_st = self.ipv6.get_status()
        net_ov = self.net.get_overview()
        boot_st = self.startup.get_status()
        rec_st = self.recovery.get_status()

        if tor_st.service_active and tor_st.bootstrap_percent >= 100 and fw_st.nat_table_present and fw_st.filter_table_present and dns_st.protected and v6_st.protected:
            overall = "ACTIVE"
        elif fw_st.filter_table_present and not tor_st.service_active:
            overall = "WARNING"  # Fail-closed active, Tor down
        elif not fw_st.filter_table_present and not tor_st.service_active:
            overall = "INACTIVE"
        else:
            overall = "NOT VERIFIED"

        return {
            "app_version": __version__,
            "os_version": detect_kali_version(),
            "overall_state": overall,
            "tor": {
                "installed": tor_st.installed,
                "service_active": tor_st.service_active,
                "bootstrap_percent": tor_st.bootstrap_percent,
                "bootstrap_summary": tor_st.bootstrap_summary,
                "control_authenticated": tor_st.control_authenticated,
                "circuits": self.tor.get_circuit_info(),
            },
            "firewall": {
                "backend": fw_st.backend,
                "available": fw_st.nftables_available,
                "nat_active": fw_st.nat_table_present,
                "filter_active": fw_st.filter_table_present,
                "fail_closed": fw_st.fail_closed,
                "allow_lan": fw_st.allow_lan,
                "conflicts": fw_st.conflicts,
                "details": fw_st.details,
                "rules_preview": self.firewall.get_managed_rules_text(),
            },
            "dns": {
                "protected": dns_st.protected,
                "nameservers": dns_st.nameservers,
                "external_resolvers": dns_st.external_resolvers_detected,
                "systemd_resolved": dns_st.systemd_resolved_active,
                "network_manager": dns_st.network_manager_active,
                "details": dns_st.details,
            },
            "ipv4": {
                "protected": v4_st.protected,
                "tcp_redirect": v4_st.tcp_redirect_active,
                "fail_closed_drop": v4_st.fail_closed_drop_active,
                "direct_connections": v4_st.direct_connections,
                "details": v4_st.details,
            },
            "ipv6": {
                "protected": v6_st.protected,
                "egress_blocked": v6_st.egress_blocked,
                "sysctl_disabled": v6_st.sysctl_disabled,
                "details": v6_st.details,
            },
            "network": {
                "primary_interface": net_ov.primary_interface,
                "active_interfaces": net_ov.active_interfaces,
                "network_manager": net_ov.network_manager_active,
                "docker": net_ov.docker_active,
                "is_vm": net_ov.is_vm,
                "vm_type": net_ov.vm_type,
            },
            "startup": {
                "enabled": boot_st.boot_protection_enabled,
                "firewall_unit": boot_st.firewall_unit_enabled,
                "service_unit": boot_st.service_unit_enabled,
                "recovery_unit": boot_st.recovery_unit_enabled,
                "last_boot_verified_at": boot_st.last_boot_verified_at,
                "last_boot_result": boot_st.last_boot_result,
            },
            "recovery": rec_st,
            "warnings": self.security.get_privacy_warnings(),
        }

    def get_logs(self, limit: int = 100, category: str | None = None, search: str | None = None) -> List[str]:
        return self.log_mgr.read_recent(limit=limit, category=category, search=search)

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        updated = self.config_mgr.update(updates)
        self._reload_managers()
        return updated

    def reset_config(self) -> Dict[str, Any]:
        restored = self.config_mgr.reset_defaults()
        self._reload_managers()
        return restored
