"""Desktop notification helper for ANON-X Privacy Center."""

from __future__ import annotations

from PySide6.QtWidgets import QSystemTrayIcon

from anonx.security_manager import run_safe


class NotificationManager:
    """Sends desktop notifications via QSystemTrayIcon with notify-send fallback."""

    def __init__(self, tray_icon: QSystemTrayIcon | None = None, enabled: bool = True) -> None:
        self.tray_icon = tray_icon
        self.enabled = enabled

    def notify(self, title: str, message: str, critical: bool = False) -> None:
        if not self.enabled:
            return
        if self.tray_icon and self.tray_icon.isVisible():
            icon = QSystemTrayIcon.Critical if critical else QSystemTrayIcon.Information
            self.tray_icon.showMessage(title, message, icon, 5000)
            return
        urgency = "critical" if critical else "normal"
        run_safe(["notify-send", "-u", urgency, "-a", "ANON-X", title, message])
