"""D-Bus system bus service for ANON-X with Polkit authorization enforcement."""

from __future__ import annotations

import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from privileged.service_api import ALLOWED_ADMIN_OPS, PrivilegedServiceAPI

BUS_NAME = "org.anonx.Manager"
OBJECT_PATH = "/org/anonx/Manager"
INTERFACE_NAME = "org.anonx.Manager"
POLKIT_ACTION_MANAGE = "org.anonx.Manager.manage"


class AnonXDBusService(dbus.service.Object):
    """Exposes strictly allowlisted ANON-X methods over the system D-Bus."""

    def __init__(self) -> None:
        bus_name = dbus.service.BusName(BUS_NAME, dbus.SystemBus())
        super().__init__(bus_name, OBJECT_PATH)
        self.api = PrivilegedServiceAPI()

    def _authorize_polkit(self, conn: dbus.Connection, sender: str, action_id: str) -> bool:
        proxy = conn.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
        authority = dbus.Interface(proxy, "org.freedesktop.PolicyKit1.Authority")
        subject = ("system-bus-name", {"name": sender})
        is_authorized, _is_challenge, _details = authority.CheckAuthorization(
            subject, action_id, {}, 1, ""
        )
        return bool(is_authorized)

    @dbus.service.method(
        INTERFACE_NAME,
        in_signature="ss",
        out_signature="s",
        sender_keyword="sender",
        connection_keyword="conn",
    )
    def Invoke(self, operation: str, payload_json: str, sender: str = "", conn: dbus.Connection | None = None) -> str:
        if operation in ALLOWED_ADMIN_OPS:
            if conn is None or not self._authorize_polkit(conn, sender, POLKIT_ACTION_MANAGE):
                raise dbus.exceptions.DBusException(
                    "org.anonx.Manager.Error.AccessDenied",
                    "Polkit authorization denied for privileged ANON-X operation.",
                )
        return self.api.execute(operation, payload_json)


def main() -> int:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    AnonXDBusService()
    loop = GLib.MainLoop()
    loop.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
