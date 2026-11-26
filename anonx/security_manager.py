"""Safe command execution, input validation, and host security checks."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence


ALLOWED_BINARIES = {
    "systemctl",
    "nft",
    "tor",
    "ip",
    "sysctl",
    "nmcli",
    "ss",
    "ps",
    "id",
    "uname",
    "cat",
    "resolvectl",
    "ufw",
    "docker",
    "notify-send",
}

_SAFE_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,15}$")


@dataclass(frozen=True)
class CommandResult:
    """Normalized subprocess execution result."""

    returncode: int
    stdout: str
    stderr: str
    command: List[str]

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandSecurityError(RuntimeError):
    """Raised when a subprocess invocation violates security rules."""


def validate_interface_name(name: str) -> str:
    """Validate a Linux network interface name."""
    if not _SAFE_IFACE_RE.match(name):
        raise ValueError(f"Invalid network interface name: {name!r}")
    return name


def validate_cidr(cidr: str) -> str:
    """Validate an IPv4 or IPv6 CIDR string."""
    ipaddress.ip_network(cidr, strict=False)
    return cidr


def run_safe(
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    timeout: int = 30,
    check_allowlist: bool = True,
) -> CommandResult:
    """Execute a system binary safely without shell interpolation."""
    if not args:
        raise CommandSecurityError("Empty command sequence.")

    exe = os.path.basename(args[0])
    if check_allowlist and exe not in ALLOWED_BINARIES:
        raise CommandSecurityError(f"Binary {exe!r} is not in ANON-X allowlist.")

    resolved = shutil.which(args[0]) or args[0]
    cmd = [resolved, *args[1:]]

    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return CommandResult(
            returncode=proc.returncode,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            command=list(cmd),
        )
    except FileNotFoundError:
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"Executable not found: {args[0]}",
            command=list(cmd),
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            returncode=124,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            command=list(cmd),
        )


class SecurityManager:
    """Host security checks and privacy-hardening advisory inspections."""

    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def detect_vpn_interfaces(self) -> List[str]:
        """Detect active VPN tunnel interfaces (tun/tap/wg/ppp)."""
        res = run_safe(["ip", "-o", "link", "show", "up"])
        if not res.ok:
            return []
        vpns: List[str] = []
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                iface = parts[1].strip().split("@")[0]
                if iface.startswith(("tun", "tap", "wg", "ppp", "nordlynx", "proton")):
                    vpns.append(iface)
        return vpns

    def detect_listening_services(self) -> List[Dict[str, str]]:
        """List non-loopback listening TCP/UDP sockets for host audit."""
        res = run_safe(["ss", "-tulnp"])
        if not res.ok:
            return []
        findings: List[Dict[str, str]] = []
        for line in res.stdout.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 5:
                continue
            proto = cols[0]
            local_addr = cols[4]
            if local_addr.startswith(("127.", "[::1]", "::1:")):
                continue
            findings.append({"proto": proto, "local_address": local_addr})
        return findings

    def detect_non_tor_browsers(self) -> List[str]:
        """Identify running standard browsers that may leak identity or fingerprint."""
        res = run_safe(["ps", "-eo", "comm"])
        if not res.ok:
            return []
        running = {line.strip().lower() for line in res.stdout.splitlines()}
        flagged = []
        for browser in ("firefox", "firefox-esr", "chromium", "chrome", "google-chrome", "brave", "opera"):
            if browser in running:
                flagged.append(browser)
        return flagged

    def get_privacy_warnings(self) -> List[str]:
        """Return actionable privacy warnings based on current host state."""
        warnings = [
            "Tor does not guarantee perfect anonymity; browser fingerprinting and account logins can still identify you.",
            "Unsupported UDP applications (e.g., WebRTC, BitTorrent, VoIP) are blocked by default and must not be routed outside Tor.",
            "Your local ISP or network provider can still observe that you are connecting to the Tor network.",
        ]
        vpns = self.detect_vpn_interfaces()
        if vpns:
            warnings.append(f"Active VPN interface(s) detected ({', '.join(vpns)}): verify routing priority to avoid conflicts.")
        browsers = self.detect_non_tor_browsers()
        if browsers:
            warnings.append(f"Non-Tor browser(s) running ({', '.join(browsers)}): prefer Tor Browser for web browsing.")
        return warnings
