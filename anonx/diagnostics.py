"""Comprehensive 16-point privacy diagnostics for ANON-X."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

from .dns_manager import DNSManager
from .firewall_manager import FirewallManager
from .ipv4_manager import IPv4Manager
from .ipv6_manager import IPv6Manager
from .network_manager import NetworkEnvironmentManager
from .recovery_manager import RecoveryManager
from .security_manager import SecurityManager
from .startup_manager import StartupManager
from .tor_manager import TorManager


@dataclass
class DiagnosticItem:
    check: str
    status: str  # PASS | WARNING | FAILED | NOT SUPPORTED
    details: str


class DiagnosticsEngine:
    """Evaluates system configuration and protection state without false PASS claims."""

    def __init__(
        self,
        tor: TorManager,
        firewall: FirewallManager,
        dns: DNSManager,
        ipv4: IPv4Manager,
        ipv6: IPv6Manager,
        net: NetworkEnvironmentManager,
        startup: StartupManager,
        recovery: RecoveryManager,
        security: SecurityManager,
    ) -> None:
        self.tor = tor
        self.firewall = firewall
        self.dns = dns
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.net = net
        self.startup = startup
        self.recovery = recovery
        self.security = security

    def run_all(self) -> Dict[str, Any]:
        items: List[DiagnosticItem] = []

        tor_st = self.tor.get_status()
        fw_st = self.firewall.get_status()
        dns_st = self.dns.get_status()
        v4_st = self.ipv4.get_status()
        v6_st = self.ipv6.get_status()
        net_ov = self.net.get_overview()
        boot_st = self.startup.get_status()
        rec_st = self.recovery.get_status()

        # 1. Tor service
        items.append(DiagnosticItem(
            "Tor Service",
            "PASS" if tor_st.service_active else ("FAILED" if tor_st.installed else "NOT SUPPORTED"),
            "tor systemd service is active" if tor_st.service_active else tor_st.bootstrap_summary,
        ))
        # 2. Tor bootstrap (never PASS merely because process is running)
        items.append(DiagnosticItem(
            "Tor Bootstrap",
            "PASS" if tor_st.bootstrap_percent >= 100 else ("WARNING" if tor_st.service_active else "FAILED"),
            f"{tor_st.bootstrap_percent}% — {tor_st.bootstrap_summary}",
        ))
        # 3. Authenticated ControlPort
        items.append(DiagnosticItem(
            "Tor ControlPort Auth",
            "PASS" if tor_st.control_authenticated else "FAILED",
            "Local cookie authentication verified" if tor_st.control_authenticated else (tor_st.error or "ControlPort unreachable"),
        ))
        # 4. nftables availability & tables
        items.append(DiagnosticItem(
            "nftables Firewall",
            "PASS" if (fw_st.nat_table_present and fw_st.filter_table_present) else ("WARNING" if fw_st.filter_table_present else "FAILED"),
            fw_st.details,
        ))
        # 5. Fail-closed policy
        items.append(DiagnosticItem(
            "Fail-Closed Policy",
            "PASS" if fw_st.fail_closed and fw_st.filter_table_present else ("WARNING" if fw_st.fail_closed else "FAILED"),
            "Non-Tor egress drop chain enforced" if fw_st.filter_table_present else "Fail-closed filter table not loaded",
        ))
        # 6. IPv4 transparent proxy
        items.append(DiagnosticItem(
            "IPv4 TCP Redirection",
            "PASS" if v4_st.protected else "FAILED",
            v4_st.details,
        ))
        # 7. Direct outbound connections
        items.append(DiagnosticItem(
            "Direct Outbound Sockets",
            "PASS" if not v4_st.direct_connections else "WARNING",
            "No non-Tor established outbound sockets detected" if not v4_st.direct_connections else f"{len(v4_st.direct_connections)} existing non-Tor socket(s) observed",
        ))
        # 8. DNS leak protection
        items.append(DiagnosticItem(
            "DNS Leak Protection",
            "PASS" if dns_st.protected else "FAILED",
            dns_st.details,
        ))
        # 9. systemd-resolved / NetworkManager
        items.append(DiagnosticItem(
            "Resolver & NetworkManager",
            "PASS" if dns_st.network_manager_active else "WARNING",
            f"NetworkManager={'active' if dns_st.network_manager_active else 'inactive'}, systemd-resolved={'active' if dns_st.systemd_resolved_active else 'inactive'}",
        ))
        # 10. IPv6 protection
        items.append(DiagnosticItem(
            "IPv6 Leak Protection",
            "PASS" if v6_st.protected else "FAILED",
            v6_st.details,
        ))
        # 11. Network interface
        items.append(DiagnosticItem(
            "Network Interface",
            "PASS" if net_ov.primary_interface else "WARNING",
            f"Primary={net_ov.primary_interface or 'none'}, Active={', '.join(net_ov.active_interfaces) or 'none'}",
        ))
        # 12. VPN conflicts
        vpns = self.security.detect_vpn_interfaces()
        items.append(DiagnosticItem(
            "VPN Conflict Check",
            "WARNING" if vpns else "PASS",
            f"Active VPN tunnel(s): {', '.join(vpns)}" if vpns else "No conflicting VPN interfaces detected",
        ))
        # 13. Docker / containers
        items.append(DiagnosticItem(
            "Docker & Containers",
            "WARNING" if net_ov.docker_active else "PASS",
            "Docker active — container bridge traffic requires separate isolation review" if net_ov.docker_active else "Docker not active",
        ))
        # 14. Virtual machine context
        items.append(DiagnosticItem(
            "Virtualization Context",
            "WARNING" if net_ov.is_vm else "PASS",
            f"Running in VM ({net_ov.vm_type}): host OS network sits outside guest firewall" if net_ov.is_vm else "Bare-metal or undetected hypervisor",
        ))
        # 15. Automatic startup
        items.append(DiagnosticItem(
            "Automatic Startup",
            "PASS" if boot_st.boot_protection_enabled else "WARNING",
            "Boot protection units enabled" if boot_st.boot_protection_enabled else "Boot protection not enabled",
        ))
        # 16. Recovery readiness
        items.append(DiagnosticItem(
            "Recovery System",
            "PASS" if rec_st["snapshot_available"] else "WARNING",
            f"Snapshot ready ({rec_st['captured_at']})" if rec_st["snapshot_available"] else "No active recovery snapshot yet",
        ))

        counts = {
            "PASS": sum(1 for i in items if i.status == "PASS"),
            "WARNING": sum(1 for i in items if i.status == "WARNING"),
            "FAILED": sum(1 for i in items if i.status == "FAILED"),
            "NOT SUPPORTED": sum(1 for i in items if i.status == "NOT SUPPORTED"),
        }

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Configuration & local state verification. External exit-IP verification requires an external check over Tor.",
            "summary": counts,
            "checks": [asdict(i) for i in items],
        }
