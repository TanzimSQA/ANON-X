"""Unified GUI-to-backend client using D-Bus (with safe local read-only fallback)."""

from __future__ import annotations

import json
from typing import Any, Dict

from privileged.service_api import ALLOWED_ADMIN_OPS, PrivilegedServiceAPI

try:
    import dbus  # type: ignore
except ImportError:  # pragma: no cover
    dbus = None

BUS_NAME = "org.anonx.Manager"
OBJECT_PATH = "/org/anonx/Manager"
INTERFACE_NAME = "org.anonx.Manager"


class BackendClient:
    """Communicates with the privileged ANON-X D-Bus service or local API."""

    def __init__(self) -> None:
        self._local_api = PrivilegedServiceAPI()

    def _invoke_dbus(self, operation: str, payload_json: str) -> Dict[str, Any]:
        if dbus is None:
            raise RuntimeError("dbus-python is not installed")
        bus = dbus.SystemBus()
        proxy = bus.get_object(BUS_NAME, OBJECT_PATH)
        iface = dbus.Interface(proxy, INTERFACE_NAME)
        raw = str(iface.Invoke(operation, payload_json))
        return json.loads(raw)

    def call(self, operation: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        payload_json = json.dumps(payload or {})
        try:
            return self._invoke_dbus(operation, payload_json)
        except Exception as dbus_exc:
            # In development or when running directly as root without D-Bus daemon,
            # allow read-only operations locally; admin operations require root or D-Bus/Polkit.
            if operation in ALLOWED_ADMIN_OPS and not self._local_api.core.security.is_root():
                return {
                    "ok": False,
                    "message": f"Privileged D-Bus/Polkit service unavailable ({dbus_exc}). Start anonx-dbus.service or run anonctl with sudo.",
                    "error": str(dbus_exc),
                }
            raw = self._local_api.execute(operation, payload_json)
            return json.loads(raw)
