"""Secure network recovery and state snapshot management for ANON-X."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .firewall_manager import FirewallManager
from .ipv6_manager import IPv6Manager


class RecoveryManager:
    """Captures pre-activation state and restores only ANON-X-changed settings."""

    def __init__(
        self,
        config: Dict[str, Any],
        logger: Any,
        firewall: FirewallManager,
        ipv6: IPv6Manager,
    ) -> None:
        self.cfg = config
        self.logger = logger
        self.firewall = firewall
        self.ipv6 = ipv6
        self.backup_dir = Path(str(config.get("general", {}).get("backup_dir", "/var/lib/anonx/backups")))
        self.state_file = self.backup_dir / "recovery_state.json"

    def has_snapshot(self) -> bool:
        return self.state_file.exists()

    def load_snapshot(self) -> Optional[Dict[str, Any]]:
        if not self.state_file.exists():
            return None
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.error("RECOVERY: Failed reading snapshot: %s", exc)
            return None

    def capture_snapshot(self, trigger: str = "start") -> Dict[str, Any]:
        """Atomically record original IPv6 sysctl and ANON-X metadata before applying changes."""
        existing = self.load_snapshot()
        # Preserve original pre-ANON-X sysctl values if a snapshot is already active
        ipv6_state = existing.get("ipv6_sysctl") if existing else self.ipv6.capture_sysctl_state()

        snapshot = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "trigger": trigger,
            "ipv6_sysctl": ipv6_state,
            "owned_tables": [
                f"ip {self.firewall.nat_table}",
                f"inet {self.firewall.filter_table}",
            ],
            "systemd_units": [
                "anonx-firewall.service",
                "anonx.service",
                "anonx-recovery.service",
            ],
            "active": True,
        }

        self.backup_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".anonx_rec_", dir=str(self.backup_dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(snapshot, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.state_file)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

        self.logger.info("RECOVERY: Captured pre-change state snapshot (%s)", trigger)
        return snapshot

    def recover(self, reason: str = "manual") -> tuple[bool, str]:
        """Remove ANON-X-owned firewall tables and restore ANON-X-modified sysctl settings."""
        self.logger.warning("RECOVERY: Triggered recovery (%s)", reason)
        snapshot = self.load_snapshot()

        fw_ok = self.firewall.remove_owned_tables()
        ipv6_ok = True
        if snapshot and snapshot.get("ipv6_sysctl"):
            ipv6_ok = self.ipv6.restore_sysctl_state(snapshot["ipv6_sysctl"])

        if self.state_file.exists():
            try:
                if snapshot:
                    snapshot["active"] = False
                    snapshot["last_recovery"] = datetime.now(timezone.utc).isoformat()
                    snapshot["last_recovery_reason"] = reason
                    self.state_file.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            except OSError as exc:
                self.logger.warning("RECOVERY: Could not update snapshot metadata: %s", exc)

        if fw_ok and ipv6_ok:
            return True, "ANON-X-owned firewall tables removed and original IPv6 settings restored."
        return False, "Partial recovery completed with warnings; check ANON-X logs."

    def get_status(self) -> Dict[str, Any]:
        snap = self.load_snapshot()
        return {
            "snapshot_available": snap is not None,
            "captured_at": snap.get("captured_at") if snap else None,
            "last_recovery": snap.get("last_recovery") if snap else None,
            "active_session": bool(snap.get("active")) if snap else False,
            "state_file": str(self.state_file),
        }
