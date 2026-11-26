"""Dedicated nftables firewall manager for ANON-X.

Guarantees:
- Never executes `nft flush ruleset` or `iptables -F`.
- Uses dedicated `anonx_nat` and `anonx_filter` tables only.
- Validates rulesets with `nft -c -f -` before atomic application.
- Enforces fail-closed egress blocking when Tor is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .security_manager import run_safe, validate_cidr


@dataclass
class FirewallStatus:
    backend: str
    nftables_available: bool
    nat_table_present: bool
    filter_table_present: bool
    fail_closed: bool
    allow_lan: bool
    conflicts: List[str]
    details: str


class FirewallError(RuntimeError):
    """Raised when firewall validation or atomic application fails."""


class FirewallManager:
    """Manages ANON-X-owned nftables tables without touching unrelated rules."""

    def __init__(self, config: Dict[str, Any], logger: Any) -> None:
        self.cfg = config
        self.fw_cfg = config.get("firewall", {})
        self.tor_cfg = config.get("tor", {})
        self.ipv6_cfg = config.get("ipv6", {})
        self.logger = logger

        self.nat_table = str(self.fw_cfg.get("nat_table_name", "anonx_nat"))
        self.filter_table = str(self.fw_cfg.get("table_name", "anonx_filter"))
        self.tor_user = str(self.tor_cfg.get("user", "debian-tor"))
        self.trans_port = int(self.tor_cfg.get("trans_port", 9040))
        self.dns_port = int(self.tor_cfg.get("dns_port", 5353))
        self.allow_dhcp = bool(self.fw_cfg.get("allow_dhcp", True))
        self.allow_lan = bool(self.fw_cfg.get("allow_lan", False))
        self.block_unsupported_udp = bool(self.fw_cfg.get("block_unsupported_udp", True))
        self.lan_cidrs = [validate_cidr(c) for c in self.fw_cfg.get("lan_cidrs", [])]

    def is_nftables_available(self) -> bool:
        return run_safe(["nft", "--version"]).ok

    def detect_conflicts(self) -> List[str]:
        """Detect other firewall managers (UFW, Docker, iptables-nft) for awareness."""
        conflicts: List[str] = []
        ufw_res = run_safe(["ufw", "status"])
        if ufw_res.ok and "active" in ufw_res.stdout.lower():
            conflicts.append("UFW is active (ANON-X preserves UFW tables and uses dedicated tables).")
        docker_res = run_safe(["systemctl", "is-active", "docker"])
        if docker_res.ok and docker_res.stdout.strip() == "active":
            conflicts.append("Docker is active (container bridge traffic may require review).")
        return conflicts

    def generate_ruleset(self, fail_closed_only: bool = False) -> str:
        """Generate atomic nftables script managing ONLY ANON-X-owned tables."""
        lines: List[str] = [
            f"add table ip {self.nat_table}",
            f"flush table ip {self.nat_table}",
            f"add table inet {self.filter_table}",
            f"flush table inet {self.filter_table}",
            "",
        ]

        if not fail_closed_only:
            lines.extend([
                f"table ip {self.nat_table} {{",
                "    chain output {",
                "        type nat hook output priority -100; policy accept;",
                '        oifname "lo" return',
                f'        meta skuid "{self.tor_user}" return',
                "        ip daddr 127.0.0.0/8 return",
            ])
            if self.allow_lan and self.lan_cidrs:
                cidr_set = ", ".join(self.lan_cidrs)
                lines.append(f"        ip daddr {{ {cidr_set} }} return")
            lines.extend([
                f"        udp dport 53 redirect to :{self.dns_port}",
                f"        tcp dport 53 redirect to :{self.dns_port}",
                f"        meta l4proto tcp redirect to :{self.trans_port}",
                "    }",
                "}",
                "",
            ])

        # Filter table (IPv4 + IPv6 via inet) enforces fail-closed egress & IPv6 blocking
        lines.extend([
            f"table inet {self.filter_table} {{",
            "    chain output {",
            "        type filter hook output priority 0; policy accept;",
            '        oifname "lo" accept',
            "        ct state established,related accept",
            f'        meta skuid "{self.tor_user}" accept',
        ])

        if self.allow_dhcp:
            lines.append("        udp sport 68 udp dport 67 accept")

        if self.allow_lan and self.lan_cidrs and not fail_closed_only:
            cidr_set = ", ".join(self.lan_cidrs)
            lines.append(f"        ip daddr {{ {cidr_set} }} accept")

        if not fail_closed_only:
            # Allow locally redirected traffic to Tor TransPort & DNSPort
            lines.extend([
                f"        ip daddr 127.0.0.1 tcp dport {{ {self.trans_port}, {self.dns_port}, 9050, 9051 }} accept",
                f"        ip daddr 127.0.0.1 udp dport {self.dns_port} accept",
            ])

        # Block all direct IPv6 egress & IPv6 DNS bypasses
        lines.append("        meta nfproto ipv6 drop")

        # Block direct external DNS on port 53/853 that escaped redirection
        lines.extend([
            "        udp dport { 53, 853 } drop",
            "        tcp dport 853 drop",
        ])

        if self.block_unsupported_udp:
            lines.append("        meta l4proto udp drop")

        # Fail-closed final catch-all for any unredirected IPv4/non-Tor egress
        lines.extend([
            "        drop",
            "    }",
            "}",
            "",
        ])
        return "\n".join(lines)

    def validate_ruleset(self, ruleset: str) -> tuple[bool, str]:
        """Dry-run validate nftables script with `nft -c -f -`."""
        res = run_safe(["nft", "-c", "-f", "-"], input_text=ruleset)
        if not res.ok:
            return False, res.stderr or "nftables validation failed"
        return True, "Ruleset syntax valid"

    def apply(self, fail_closed_only: bool = False) -> None:
        """Validate and atomically apply ANON-X nftables rules."""
        ruleset = self.generate_ruleset(fail_closed_only=fail_closed_only)
        ok, msg = self.validate_ruleset(ruleset)
        if not ok:
            self.logger.error("FIREWALL: Validation failed: %s", msg)
            raise FirewallError(f"Firewall validation failed: {msg}")

        res = run_safe(["nft", "-f", "-"], input_text=ruleset)
        if not res.ok:
            self.logger.error("FIREWALL: Atomic apply failed: %s", res.stderr)
            raise FirewallError(f"Firewall apply failed: {res.stderr}")

        mode = "FAIL-CLOSED" if fail_closed_only else "TOR-TRANSPARENT"
        self.logger.info("FIREWALL: Applied %s nftables ruleset", mode)

    def remove_owned_tables(self) -> bool:
        """Remove ONLY ANON-X-owned nftables tables, preserving all other firewall rules."""
        ok_all = True
        for family, table in (("ip", self.nat_table), ("inet", self.filter_table)):
            check = run_safe(["nft", "list", "table", family, table])
            if check.ok:
                rem = run_safe(["nft", "delete", "table", family, table])
                if not rem.ok:
                    self.logger.error("FIREWALL: Failed deleting %s %s: %s", family, table, rem.stderr)
                    ok_all = False
                else:
                    self.logger.info("FIREWALL: Removed ANON-X table %s %s", family, table)
        return ok_all

    def get_managed_rules_text(self) -> str:
        """Return currently active ANON-X nftables rules for inspection."""
        chunks: List[str] = []
        for family, table in (("ip", self.nat_table), ("inet", self.filter_table)):
            res = run_safe(["nft", "list", "table", family, table])
            if res.ok and res.stdout:
                chunks.append(res.stdout)
        return "\n\n".join(chunks) if chunks else "No ANON-X nftables tables loaded."

    def get_status(self) -> FirewallStatus:
        avail = self.is_nftables_available()
        if not avail:
            return FirewallStatus("nftables", False, False, False, bool(self.fw_cfg.get("fail_closed", True)), self.allow_lan, [], "nft binary unavailable")
        nat_ok = run_safe(["nft", "list", "table", "ip", self.nat_table]).ok
        flt_ok = run_safe(["nft", "list", "table", "inet", self.filter_table]).ok
        conflicts = self.detect_conflicts()
        details = "Active (NAT + Filter)" if (nat_ok and flt_ok) else ("Fail-closed filter only" if flt_ok else "Inactive")
        return FirewallStatus("nftables", True, nat_ok, flt_ok, bool(self.fw_cfg.get("fail_closed", True)), self.allow_lan, conflicts, details)
