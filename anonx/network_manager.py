"""Network interface, NetworkManager, Docker, and VM environment detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .security_manager import run_safe


@dataclass
class NetworkOverview:
    primary_interface: Optional[str]
    network_manager_active: bool
    docker_active: bool
    is_vm: bool
    vm_type: Optional[str]
    active_interfaces: List[str]


class NetworkEnvironmentManager:
    """Detects host network interfaces, NetworkManager, Docker, and virtualization context."""

    def get_primary_interface(self) -> Optional[str]:
        res = run_safe(["ip", "route", "show", "default"])
        if not res.ok or not res.stdout:
            return None
        parts = res.stdout.splitlines()[0].split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None

    def get_active_interfaces(self) -> List[str]:
        res = run_safe(["ip", "-o", "link", "show", "up"])
        if not res.ok:
            return []
        ifaces: List[str] = []
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                ifaces.append(parts[1].strip().split("@")[0])
        return ifaces

    def detect_vm(self) -> tuple[bool, Optional[str]]:
        res = run_safe(["systemd-detect-virt"], check_allowlist=False)
        if res.ok and res.stdout and res.stdout.strip() != "none":
            return True, res.stdout.strip()
        return False, None

    def get_overview(self) -> NetworkOverview:
        nm = run_safe(["systemctl", "is-active", "NetworkManager"])
        dk = run_safe(["systemctl", "is-active", "docker"])
        is_vm, vm_type = self.detect_vm()
        return NetworkOverview(
            primary_interface=self.get_primary_interface(),
            network_manager_active=nm.ok and nm.stdout.strip() == "active",
            docker_active=dk.ok and dk.stdout.strip() == "active",
            is_vm=is_vm,
            vm_type=vm_type,
            active_interfaces=self.get_active_interfaces(),
        )
