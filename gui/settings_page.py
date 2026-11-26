"""Page 8 — Settings & Privacy Defaults."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class SettingsPage(QWidget):
    save_requested = Signal(dict)
    reset_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(14)

        title = QLabel("SETTINGS & PRIVACY DEFAULTS")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setSpacing(12)

        self.chk_fail_closed = QCheckBox("Enforce Fail-Closed Firewall (block internet if Tor is unavailable)")
        self.chk_udp_block = QCheckBox("Block Unsupported UDP Traffic by Default")
        self.chk_allow_lan = QCheckBox("Allow Local Network (LAN) Access — Warning: LAN traffic bypasses Tor")
        self.chk_ipv6_sysctl = QCheckBox("Disable IPv6 via sysctl while ANON-X is active")
        self.chk_tray = QCheckBox("Minimize to System Tray on Window Close (never stops background service)")
        self.chk_notify = QCheckBox("Enable Desktop Notifications")
        self.chk_gui_autostart = QCheckBox("Start ANON-X GUI at Desktop Login")

        lbl_log = QLabel("Logging Level:")
        self.cmb_log = QComboBox()
        self.cmb_log.addItems(["INFO", "DEBUG", "WARNING", "ERROR"])

        for w in (
            self.chk_fail_closed, self.chk_udp_block, self.chk_allow_lan,
            self.chk_ipv6_sysctl, self.chk_tray, self.chk_notify, self.chk_gui_autostart,
        ):
            cl.addWidget(w)

        row_log = QHBoxLayout()
        row_log.addWidget(lbl_log)
        row_log.addWidget(self.cmb_log)
        row_log.addStretch()
        cl.addLayout(row_log)
        root.addWidget(card)

        btns = QHBoxLayout()
        btn_reset = QPushButton("Restore Default Settings")
        btn_reset.setObjectName("SecondaryButton")
        btn_reset.clicked.connect(self.reset_requested.emit)
        btn_save = QPushButton("Save & Validate Settings")
        btn_save.setObjectName("PrimaryAction")
        btn_save.clicked.connect(self._emit_save)
        btns.addWidget(btn_reset)
        btns.addStretch()
        btns.addWidget(btn_save)
        root.addLayout(btns)
        root.addStretch()

    def load_config(self, cfg: Dict[str, Any]) -> None:
        fw = cfg.get("firewall", {})
        ipv6 = cfg.get("ipv6", {})
        gui = cfg.get("gui", {})
        startup = cfg.get("startup", {})
        gen = cfg.get("general", {})

        self.chk_fail_closed.setChecked(bool(fw.get("fail_closed", True)))
        self.chk_udp_block.setChecked(bool(fw.get("block_unsupported_udp", True)))
        self.chk_allow_lan.setChecked(bool(fw.get("allow_lan", False)))
        self.chk_ipv6_sysctl.setChecked(bool(ipv6.get("disable_sysctl_ipv6", True)))
        self.chk_tray.setChecked(bool(gui.get("minimize_to_tray", True)))
        self.chk_notify.setChecked(bool(gui.get("notifications_enabled", True)))
        self.chk_gui_autostart.setChecked(bool(startup.get("gui_autostart", False)))
        idx = self.cmb_log.findText(str(gen.get("log_level", "INFO")).upper())
        if idx >= 0:
            self.cmb_log.setCurrentIndex(idx)

    def _emit_save(self) -> None:
        updates = {
            "general": {"log_level": self.cmb_log.currentText()},
            "firewall": {
                "fail_closed": self.chk_fail_closed.isChecked(),
                "block_unsupported_udp": self.chk_udp_block.isChecked(),
                "allow_lan": self.chk_allow_lan.isChecked(),
            },
            "ipv6": {"disable_sysctl_ipv6": self.chk_ipv6_sysctl.isChecked()},
            "gui": {
                "minimize_to_tray": self.chk_tray.isChecked(),
                "notifications_enabled": self.chk_notify.isChecked(),
            },
            "startup": {"gui_autostart": self.chk_gui_autostart.isChecked()},
        }
        self.save_requested.emit(updates)
