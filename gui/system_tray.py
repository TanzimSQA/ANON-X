"""Linux system tray integration for ANON-X Privacy Center."""

from __future__ import annotations

from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QMenu, QSystemTrayIcon


class AnonXTrayIcon(QSystemTrayIcon):
    """System tray icon allowing quick status/controls without stopping background service on GUI close."""

    def __init__(self, icon: QIcon, parent=None) -> None:
        super().__init__(icon, parent)
        self.setToolTip("ANON-X Privacy Center")

        menu = QMenu(parent)
        self.act_status = QAction("Status: Checking...", menu)
        self.act_status.setEnabled(False)
        self.act_open = QAction("Open ANON-X", menu)
        self.act_enable = QAction("Enable Privacy", menu)
        self.act_disable = QAction("Disable Privacy", menu)
        self.act_diag = QAction("Run Diagnostics", menu)
        self.act_quit = QAction("Exit GUI (Service Keeps Running)", menu)

        menu.addAction(self.act_status)
        menu.addSeparator()
        menu.addAction(self.act_open)
        menu.addAction(self.act_enable)
        menu.addAction(self.act_disable)
        menu.addAction(self.act_diag)
        menu.addSeparator()
        menu.addAction(self.act_quit)

        self.setContextMenu(menu)

    def update_state_label(self, state: str) -> None:
        self.act_status.setText(f"Status: {state}")
        self.setToolTip(f"ANON-X Privacy Center — {state}")
