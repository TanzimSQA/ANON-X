"""Page 6 — Automatic Startup Protection."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .widgets import StatusCard


class StartupPage(QWidget):
    boot_enable_requested = Signal()
    boot_disable_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(14)

        top = QHBoxLayout()
        title = QLabel("AUTOMATIC STARTUP PROTECTION")
        title.setObjectName("PageTitle")
        btn_en = QPushButton("Enable at Boot")
        btn_en.setObjectName("PrimaryAction")
        btn_en.clicked.connect(self.boot_enable_requested.emit)
        btn_dis = QPushButton("Disable at Boot")
        btn_dis.setObjectName("SecondaryButton")
        btn_dis.clicked.connect(self.boot_disable_requested.emit)
        top.addWidget(title)
        top.addStretch()
        top.addWidget(btn_dis)
        top.addWidget(btn_en)
        root.addLayout(top)

        self.card_boot = StatusCard("Systemd Boot Protection")
        self.card_units = StatusCard("Service Units & Independence")
        self.card_last = StatusCard("Last Boot Verification")
        root.addWidget(self.card_boot)
        root.addWidget(self.card_units)
        root.addWidget(self.card_last)
        root.addStretch()

    def update_status(self, st: Dict[str, Any]) -> None:
        boot = st["startup"]
        self.card_boot.update_card(
            "ENABLED" if boot["enabled"] else "DISABLED",
            "Boot Protection Enabled" if boot["enabled"] else "Boot Protection Disabled",
            "Background protection runs via systemd independently of the GUI.",
        )
        self.card_units.update_card(
            "ACTIVE" if boot["firewall_unit"] and boot["service_unit"] else "INACTIVE",
            f"Firewall: {boot['firewall_unit']} | Service: {boot['service_unit']} | Recovery: {boot['recovery_unit']}",
            "anonx-firewall.service activates fail-closed rules before normal network traffic.",
        )
        self.card_last.update_card(
            "PASS" if boot["last_boot_result"] == "PASS" else "NOT VERIFIED",
            boot["last_boot_result"] or "No boot verification recorded",
            boot["last_boot_verified_at"] or "",
        )
