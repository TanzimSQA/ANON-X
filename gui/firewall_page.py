"""Page 5 — Firewall Center (Read-only inspection of ANON-X nftables tables)."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtWidgets import QLabel, QPlainTextEdit, QVBoxLayout, QWidget

from .widgets import StatusCard


class FirewallPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(12)

        title = QLabel("FIREWALL CENTER (NFTABLES)")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        self.card_fw = StatusCard("ANON-X Managed Firewall Tables")
        root.addWidget(self.card_fw)

        lbl_rules = QLabel("ACTIVE ANON-X RULESET (READ-ONLY — UNRELATED TABLES PRESERVED)")
        lbl_rules.setObjectName("CardTitle")
        root.addWidget(lbl_rules)

        self.txt_rules = QPlainTextEdit()
        self.txt_rules.setReadOnly(True)
        root.addWidget(self.txt_rules)

    def update_status(self, st: Dict[str, Any]) -> None:
        fw = st["firewall"]
        self.card_fw.update_card(
            "ACTIVE" if fw["filter_active"] else "INACTIVE",
            fw["details"],
            f"Fail-Closed: {fw['fail_closed']} | LAN Allowed: {fw['allow_lan']} | Conflicts: {len(fw['conflicts'])}",
        )
        self.txt_rules.setPlainText(fw.get("rules_preview", ""))
