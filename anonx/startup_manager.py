"""Systemd boot protection and startup verification manager."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .security_manager import run_safe


@dataclass
class BootStatus:
    firewall_unit_enabled: bool
    service_unit_enabled: bool
    recovery_unit_enabled: bool
    boot_protection_enabled: bool
    last_boot_verified_at: str | None
    last_boot_result: str | None


class StartupManager:
    """Manages ANON-X systemd units for automatic fail-closed boot protection."""

    UNITS = ("anonx-firewall.service", "anonx.service", "anonx-recovery.service")

    def __init__(self, config: Dict[str, Any], logger: Any) -> None:
        self.cfg = config
        self.logger = logger
        self.state_dir = Path(str(config.get("general", {}).get("state_dir", "/var/lib/anonx")))
        self.boot_record = self.state_dir / "boot_status.json"

    def _is_enabled(self, unit: str) -> bool:
        res = run_safe(["systemctl", "is-enabled", unit])
        return res.ok and res.stdout.strip() == "enabled"

    def enable_boot(self) -> tuple[bool, str]:
        run_safe(["systemctl", "daemon-reload"])
        for unit in self.UNITS:
            res = run_safe(["systemctl", "enable", unit])
            if not res.ok:
                self.logger.error("STARTUP: Failed to enable %s: %s", unit, res.stderr)
                return False, f"Failed to enable {unit}: {res.stderr}"
        self.logger.info("STARTUP: Enabled automatic boot protection units")
        return True, "Automatic boot protection enabled (anonx-firewall, anonx, anonx-recovery)."

    def disable_boot(self) -> tuple[bool, str]:
        for unit in self.UNITS:
            run_safe(["systemctl", "disable", unit])
        self.logger.info("STARTUP: Disabled automatic boot protection units")
        return True, "Automatic boot protection disabled."

    def record_boot_verification(self, success: bool, summary: str) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": success,
                "summary": summary,
            }
            self.boot_record.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            self.logger.warning("STARTUP: Could not persist boot verification record: %s", exc)

    def get_status(self) -> BootStatus:
        fw_en = self._is_enabled("anonx-firewall.service")
        svc_en = self._is_enabled("anonx.service")
        rec_en = self._is_enabled("anonx-recovery.service")
        last_ts = None
        last_res = None
        if self.boot_record.exists():
            try:
                data = json.loads(self.boot_record.read_text(encoding="utf-8"))
                last_ts = data.get("timestamp")
                last_res = "PASS" if data.get("success") else f"FAILED: {data.get('summary')}"
            except (OSError, json.JSONDecodeError):
                pass
        return BootStatus(
            firewall_unit_enabled=fw_en,
            service_unit_enabled=svc_en,
            recovery_unit_enabled=rec_en,
            boot_protection_enabled=fw_en and svc_en,
            last_boot_verified_at=last_ts,
            last_boot_result=last_res,
        )
