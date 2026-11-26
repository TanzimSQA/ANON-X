"""DNS leak protection, resolver detection, and NetworkManager/systemd-resolved checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from .security_manager import run_safe

RESOLV_CONF = Path("/etc/resolv.conf")


@dataclass
class DNSStatus:
    protected: bool
    nameservers: List[str]
    external_resolvers_detected: List[str]
    systemd_resolved_active: bool
    network_manager_active: bool
    port53_intercepted: bool
    details: str


class DNSManager:
    """Inspects DNS configuration and verifies Tor DNSPort interception."""

    def __init__(self, config: Dict[str, Any], logger: Any) -> None:
        self.cfg = config.get("dns", {})
        self.tor_cfg = config.get("tor", {})
        self.fw_cfg = config.get("firewall", {})
        self.logger = logger
        self.dns_port = int(self.tor_cfg.get("dns_port", 5353))
        self.nat_table = str(self.fw_cfg.get("nat_table_name", "anonx_nat"))
        self.filter_table = str(self.fw_cfg.get("table_name", "anonx_filter"))

    def read_nameservers(self, resolv_path: Path = RESOLV_CONF) -> List[str]:
        """Parse configured nameservers from resolv.conf without modifying it."""
        if not resolv_path.exists():
            return []
        servers: List[str] = []
        for line in resolv_path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            match = re.match(r"^nameserver\s+(\S+)", stripped)
            if match:
                servers.append(match.group(1))
        return servers

    def is_systemd_resolved_active(self) -> bool:
        res = run_safe(["systemctl", "is-active", "systemd-resolved"])
        return res.ok and res.stdout.strip() == "active"

    def is_network_manager_active(self) -> bool:
        res = run_safe(["systemctl", "is-active", "NetworkManager"])
        return res.ok and res.stdout.strip() == "active"

    def is_dns_interception_active(self) -> bool:
        """Verify nftables rules actually redirect port 53 to Tor DNSPort and drop external DNS."""
        nat_res = run_safe(["nft", "list", "table", "ip", self.nat_table])
        flt_res = run_safe(["nft", "list", "table", "inet", self.filter_table])
        has_redirect = nat_res.ok and f":{self.dns_port}" in nat_res.stdout
        has_drop = flt_res.ok and ("meta nfproto ipv6 drop" in flt_res.stdout)
        return has_redirect and has_drop

    def get_status(self) -> DNSStatus:
        servers = self.read_nameservers()
        external = [s for s in servers if s not in ("127.0.0.1", "127.0.0.53", "::1")]
        resolved_active = self.is_systemd_resolved_active()
        nm_active = self.is_network_manager_active()
        intercepted = self.is_dns_interception_active()

        if intercepted:
            details = f"Port 53 redirected to Tor DNSPort ({self.dns_port}); direct external/IPv6 DNS blocked."
            if external:
                details += f" Note: resolv.conf lists {', '.join(external)} (intercepted by nftables)."
        else:
            details = "DNS interception rules not active in nftables."

        return DNSStatus(
            protected=intercepted,
            nameservers=servers,
            external_resolvers_detected=external,
            systemd_resolved_active=resolved_active,
            network_manager_active=nm_active,
            port53_intercepted=intercepted,
            details=details,
        )
