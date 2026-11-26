"""Strict allowlisted API dispatcher for the privileged ANON-X backend."""

from __future__ import annotations

import json
from typing import Any, Dict

from anonx.core import AnonXCore

ALLOWED_READ_OPS = {
    "get_status",
    "run_diagnostics",
    "get_logs",
    "get_config",
}

ALLOWED_ADMIN_OPS = {
    "start_protection",
    "stop_protection",
    "restart_protection",
    "new_identity",
    "boot_enable",
    "boot_disable",
    "recover",
    "update_config",
    "reset_config",
}


class PrivilegedServiceAPI:
    """Validates and executes strictly allowlisted ANON-X operations."""

    def __init__(self, core: AnonXCore | None = None) -> None:
        self.core = core or AnonXCore()

    def execute(self, operation: str, payload_json: str = "{}") -> str:
        if operation not in ALLOWED_READ_OPS and operation not in ALLOWED_ADMIN_OPS:
            return json.dumps({"ok": False, "error": f"Operation {operation!r} is not allowlisted."})

        try:
            payload: Dict[str, Any] = json.loads(payload_json) if payload_json else {}
            if not isinstance(payload, dict):
                return json.dumps({"ok": False, "error": "Payload must be a JSON object."})
        except json.JSONDecodeError as exc:
            return json.dumps({"ok": False, "error": f"Invalid JSON payload: {exc}"})

        if operation == "get_status":
            return json.dumps({"ok": True, "data": self.core.get_status()})
        if operation == "run_diagnostics":
            return json.dumps({"ok": True, "data": self.core.verify()})
        if operation == "get_logs":
            limit = int(payload.get("limit", 100))
            category = str(payload.get("category", "ALL"))
            search = str(payload.get("search", ""))
            return json.dumps({"ok": True, "data": self.core.get_logs(limit=limit, category=category, search=search)})
        if operation == "get_config":
            return json.dumps({"ok": True, "data": self.core.config_mgr.data})
        if operation == "start_protection":
            ok, msg = self.core.start_protection()
            return json.dumps({"ok": ok, "message": msg})
        if operation == "stop_protection":
            ok, msg = self.core.stop_protection()
            return json.dumps({"ok": ok, "message": msg})
        if operation == "restart_protection":
            ok, msg = self.core.restart_protection()
            return json.dumps({"ok": ok, "message": msg})
        if operation == "new_identity":
            ok, msg = self.core.new_identity()
            return json.dumps({"ok": ok, "message": msg})
        if operation == "boot_enable":
            ok, msg = self.core.startup.enable_boot()
            return json.dumps({"ok": ok, "message": msg})
        if operation == "boot_disable":
            ok, msg = self.core.startup.disable_boot()
            return json.dumps({"ok": ok, "message": msg})
        if operation == "recover":
            ok, msg = self.core.recovery.recover(reason="gui-recovery")
            return json.dumps({"ok": ok, "message": msg})
        if operation == "update_config":
            updates = payload.get("updates", {})
            updated = self.core.update_config(updates)
            return json.dumps({"ok": True, "data": updated, "message": "Configuration updated."})
        if operation == "reset_config":
            restored = self.core.reset_config()
            return json.dumps({"ok": True, "data": restored, "message": "Default settings restored."})

        return json.dumps({"ok": False, "error": "Unhandled operation."})
