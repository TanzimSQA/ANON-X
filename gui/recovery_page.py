"""Page 9 — Recovery Center."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFrame, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from .widgets import StatusCard


class RecoveryPage(QWidget):
    recover_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(14)

        title = QLabel("RECOVERY CENTER")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        self.card_snap = StatusCard("Recovery Snapshot")
        self.card_fw = StatusCard("Current Firewall State")
        root.addWidget(self.card_snap)
        root.addWidget(self.card_fw)

        box = QFrame()
        box.setObjectName("Card")
        bl = QVBoxLayout(box)
        lbl_warn = QLabel(
            "EMERGENCY NETWORK RECOVERY\n"
            "This removes ONLY ANON-X-owned nftables tables and restores IPv6 settings modified by ANON-X. "
            "Unrelated UFW, Docker, or NetworkManager rules are preserved. "
            "Your system will return to direct public network connectivity."
        )
        lbl_warn.setWordWrap(True)
        lbl_warn.setStyleSheet("color: #fbbf24;")

        btn_rec = QPushButton("TRIGGER EMERGENCY RECOVERY")
        btn_rec.setObjectName("DangerAction")
        btn_rec.clicked.connect(self._confirm_recover)

        bl.addWidget(lbl_warn)
        bl.addWidget(btn_rec)
        root.addWidget(box)
        root.addStretch()

    def _confirm_recover(self) -> None:
        ans = QMessageBox.warning(
            self,
            "Confirm Emergency Recovery",
            "Emergency recovery will disable Tor routing and restore direct network access. Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if ans == QMessageBox.Yes:
            self.recover_requested.emit()

    def update_status(self, st: Dict[str, Any]) -> None:
        rec = st["recovery"]
        fw = st["firewall"]
        self.card_snap.update_card(
            "ACTIVE" if rec["snapshot_available"] else "NOT VERIFIED",
            "Snapshot Available" if rec["snapshot_available"] else "No Snapshot Recorded",
            f"Captured: {rec['captured_at'] or 'N/A'} | Last Recovery: {rec['last_recovery'] or 'Never'}",
        )
        self.card_fw.update_card(
            "ACTIVE" if fw["filter_active"] else "INACTIVE",
            fw["details"],
            "Only ANON-X-owned tables will be removed during recovery.",
        )
