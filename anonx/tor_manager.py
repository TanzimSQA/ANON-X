"""Tor daemon management, configuration, bootstrap verification, and authenticated ControlPort client."""

from __future__ import annotations

import binascii
import os
import re
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .security_manager import run_safe


@dataclass
class TorStatus:
    installed: bool
    service_active: bool
    bootstrap_percent: int
    bootstrap_summary: str
    control_authenticated: bool
    pid: Optional[int] = None
    error: Optional[str] = None


class TorControlError(RuntimeError):
    """Raised when authenticated Tor ControlPort communication fails."""


class TorManager:
    """Manages Tor configuration, systemd lifecycle, and authenticated ControlPort commands."""

    def __init__(self, config: Dict[str, Any], logger: Any) -> None:
        self.cfg = config.get("tor", {})
        self.logger = logger
        self.service_name = str(self.cfg.get("service_name", "tor"))
        self.tor_user = str(self.cfg.get("user", "debian-tor"))
        self.torrc_path = Path(str(self.cfg.get("torrc_path", "/etc/tor/torrc")))
        self.dropin_path = Path(str(self.cfg.get("torrc_dropin", "/etc/tor/torrc.d/99-anonx.conf")))
        self.trans_port = int(self.cfg.get("trans_port", 9040))
        self.dns_port = int(self.cfg.get("dns_port", 5353))
        self.socks_port = int(self.cfg.get("socks_port", 9050))
        self.control_port = int(self.cfg.get("control_port", 9051))
        self.cookie_file = Path(str(self.cfg.get("cookie_auth_file", "/run/tor/control.authcookie")))
        self.virtual_net = str(self.cfg.get("virtual_addr_network", "10.192.0.0/10"))
        self.bootstrap_timeout = int(self.cfg.get("bootstrap_timeout_sec", 90))

    def is_installed(self) -> bool:
        res = run_safe(["tor", "--version"])
        return res.ok

    def render_dropin_config(self) -> str:
        """Generate dedicated Tor drop-in configuration with authenticated local ControlPort."""
        return "\n".join([
            "# Managed by ANON-X — do not edit manually",
            f"VirtualAddrNetworkIPv4 {self.virtual_net}",
            "AutomapHostsOnResolve 1",
            f"TransPort 127.0.0.1:{self.trans_port}",
            f"DNSPort 127.0.0.1:{self.dns_port}",
            f"SocksPort 127.0.0.1:{self.socks_port}",
            f"ControlPort 127.0.0.1:{self.control_port}",
            "CookieAuthentication 1",
            "CookieAuthFileGroupReadable 1",
            f"CookieAuthFile {self.cookie_file}",
            "AvoidDiskWrites 1",
            "",
        ])

    def ensure_configured(self) -> None:
        """Write ANON-X Tor drop-in config atomically and ensure torrc includes torrc.d."""
        self.dropin_path.parent.mkdir(parents=True, exist_ok=True)
        content = self.render_dropin_config()
        fd, tmp = tempfile.mkstemp(prefix=".anonx_tor_", dir=str(self.dropin_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                os.chmod(tmp, 0o644)
            os.replace(tmp, self.dropin_path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

        if self.torrc_path.exists():
            torrc_text = self.torrc_path.read_text(encoding="utf-8", errors="replace")
            include_line = f"%include {self.dropin_path.parent}/*.conf"
            if str(self.dropin_path.parent) not in torrc_text:
                with self.torrc_path.open("a", encoding="utf-8") as handle:
                    handle.write(f"\n# ANON-X drop-in include\n{include_line}\n")

        self.logger.info("TOR: Updated drop-in configuration at %s", self.dropin_path)

    def start(self) -> bool:
        self.ensure_configured()
        res = run_safe(["systemctl", "restart", self.service_name], timeout=45)
        if not res.ok:
            self.logger.error("TOR: Failed to start %s: %s", self.service_name, res.stderr)
            return False
        self.logger.info("TOR: Service %s started via systemd", self.service_name)
        return True

    def stop(self) -> bool:
        res = run_safe(["systemctl", "stop", self.service_name], timeout=30)
        if not res.ok:
            self.logger.error("TOR: Failed to stop %s: %s", self.service_name, res.stderr)
            return False
        self.logger.info("TOR: Service %s stopped", self.service_name)
        return True

    def restart(self) -> bool:
        return self.start()

    def is_service_active(self) -> bool:
        res = run_safe(["systemctl", "is-active", self.service_name])
        return res.ok and res.stdout.strip() == "active"

    def _control_command(self, commands: List[str]) -> List[str]:
        """Execute authenticated commands against local Tor ControlPort using cookie auth."""
        if not self.cookie_file.exists():
            raise TorControlError(f"Tor cookie auth file not found: {self.cookie_file}")
        cookie_bytes = self.cookie_file.read_bytes()
        cookie_hex = binascii.hexlify(cookie_bytes).decode("ascii")

        responses: List[str] = []
        with socket.create_connection(("127.0.0.1", self.control_port), timeout=5.0) as sock:
            f = sock.makefile("rw", encoding="utf-8", errors="replace", newline="\r\n")
            f.write(f"AUTHENTICATE {cookie_hex}\r\n")
            f.flush()
            auth_resp = f.readline().strip()
            if not auth_resp.startswith("250"):
                raise TorControlError(f"Tor ControlPort authentication failed: {auth_resp}")

            for cmd in commands:
                f.write(f"{cmd}\r\n")
                f.flush()
                lines: List[str] = []
                while True:
                    line = f.readline()
                    if not line:
                        break
                    clean = line.rstrip("\r\n")
                    lines.append(clean)
                    if re.match(r"^\d{3} ", clean):
                        break
                responses.append("\n".join(lines))

            f.write("QUIT\r\n")
            f.flush()
        return responses

    def get_bootstrap_status(self) -> tuple[int, str]:
        """Query Tor ControlPort for bootstrap progress (0-100)."""
        resps = self._control_command(["GETINFO status/bootstrap-phase"])
        raw = resps[0] if resps else ""
        pct_match = re.search(r"PROGRESS=(\d+)", raw)
        sum_match = re.search(r'SUMMARY="([^"]*)"', raw)
        pct = int(pct_match.group(1)) if pct_match else 0
        summary = sum_match.group(1) if sum_match else "Unknown"
        return pct, summary

    def wait_for_bootstrap(self, timeout_sec: Optional[int] = None) -> tuple[bool, int, str]:
        """Poll Tor bootstrap progress until 100% or timeout."""
        deadline = time.monotonic() + (timeout_sec or self.bootstrap_timeout)
        last_pct = 0
        last_summary = "Starting"
        while time.monotonic() < deadline:
            if not self.is_service_active():
                return False, last_pct, "Tor systemd service is not active"
            try:
                last_pct, last_summary = self.get_bootstrap_status()
                if last_pct >= 100:
                    self.logger.info("TOR: Bootstrap complete (100%%)")
                    return True, 100, last_summary
            except TorControlError as exc:
                last_summary = str(exc)
            time.sleep(2.0)
        self.logger.error("TOR: Bootstrap timed out at %d%% (%s)", last_pct, last_summary)
        return False, last_pct, last_summary

    def request_new_identity(self) -> tuple[bool, str]:
        """Send SIGNAL NEWNYM over authenticated ControlPort."""
        try:
            resps = self._control_command(["SIGNAL NEWNYM"])
            reply = resps[0] if resps else ""
            if reply.startswith("250"):
                self.logger.info("TOR: New circuit identity requested (SIGNAL NEWNYM)")
                return True, "New Tor circuit requested. Note: this does not guarantee a different exit IP or reset browser state."
            return False, f"Unexpected ControlPort reply: {reply}"
        except TorControlError as exc:
            self.logger.error("TOR: New identity request failed: %s", exc)
            return False, str(exc)

    def get_circuit_info(self) -> List[str]:
        """Return sanitized active circuit summaries when safely available."""
        try:
            resps = self._control_command(["GETINFO circuit-status"])
            lines = []
            for line in (resps[0] if resps else "").splitlines():
                if " BUILT " in line:
                    lines.append(line.strip())
            return lines[:10]
        except TorControlError:
            return []

    def get_status(self) -> TorStatus:
        installed = self.is_installed()
        active = self.is_service_active() if installed else False
        if not installed:
            return TorStatus(False, False, 0, "Tor binary not installed", False)
        if not active:
            return TorStatus(True, False, 0, "Tor service inactive", False)
        try:
            pct, summary = self.get_bootstrap_status()
            return TorStatus(True, True, pct, summary, True)
        except TorControlError as exc:
            return TorStatus(True, True, 0, f"ControlPort unavailable: {exc}", False, error=str(exc))
