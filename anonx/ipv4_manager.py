"""IPv4 transparent routing verification and direct-connection detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .security_manager import run_safe


@dataclass
class IPv4Status:
    protected: bool
    tcp_redirect_active: bool
    fail_closed_drop_active: bool
    direct_connections: List[str]
    details: str


class IPv4Manager:
    """Verifies IPv4 Tor transparent redirection and checks for direct outbound connections."""

    def __init__(self, config: Dict[str, Any], logger: Any) -> None:
        self.fw_cfg = config.get("firewall", {})
        self.tor_cfg = config.get("tor", {})
        self.logger = logger
        self.nat_table = str(self.fw_cfg.get("nat_table_name", "anonx_nat"))
        self.filter_table = str(self.fw_cfg.get("table_name", "anonx_filter"))
        self.trans_port = int(self.tor_cfg.get("trans_port", 9040))

    def detect_direct_outbound_sockets(self) -> List[str]:
        """Inspect established non-loopback sockets (excluding Tor process) for diagnostics."""
        res = run_safe(["ss", "-tunap", "state", "established"])
        if not res.ok:
            return []
        direct: List[str] = []
        for line in res.stdout.splitlines()[1:]:
            if "127.0.0.1:" in line or "[::1]:" in line:
                continue
            if '"tor"' in line or "debian-tor" in line:
                continue
            direct.append(line.strip())
        return direct[:15]

    def get_status(self) -> IPv4Status:
        nat_res = run_safe(["nft", "list", "table", "ip", self.nat_table])
        flt_res = run_safe(["nft", "list", "table", "inet", self.filter_table])
        tcp_redir = nat_res.ok and f":{self.trans_port}" in nat_res.stdout
        fail_drop = flt_res.ok and "drop" in flt_res.stdout
        direct = self.detect_direct_outbound_sockets()
        protected = tcp_redir and fail_drop
        details = (
            f"TCP redirected to TransPort :{self.trans_port}; unsupported traffic dropped."
            if protected
            else "IPv4 Tor redirection is not active."
        )
        return IPv4Status(
            protected=protected,
            tcp_redirect_active=tcp_redir,
            fail_closed_drop_active=fail_drop,
            direct_connections=direct,
            details=details,
        )
