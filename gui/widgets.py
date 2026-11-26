"""Reusable styled UI widgets for ANON-X Privacy Center."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout


BADGE_STYLES = {
    "ACTIVE": "background-color: #064e3b; color: #34d399; border: 1px solid #10b981;",
    "PROTECTED": "background-color: #064e3b; color: #34d399; border: 1px solid #10b981;",
    "PASS": "background-color: #064e3b; color: #34d399; border: 1px solid #10b981;",
    "ENABLED": "background-color: #064e3b; color: #34d399; border: 1px solid #10b981;",
    "WARNING": "background-color: #451a03; color: #fbbf24; border: 1px solid #f59e0b;",
    "FAILED": "background-color: #450a0a; color: #f87171; border: 1px solid #ef4444;",
    "INACTIVE": "background-color: #1f2937; color: #9ca3af; border: 1px solid #4b5563;",
    "DISABLED": "background-color: #1f2937; color: #9ca3af; border: 1px solid #4b5563;",
    "NOT VERIFIED": "background-color: #1f2937; color: #9ca3af; border: 1px solid #4b5563;",
    "NOT SUPPORTED": "background-color: #312e81; color: #a5b4fc; border: 1px solid #6366f1;",
}


def apply_badge_style(label: QLabel, state: str) -> None:
    upper = state.upper()
    label.setText(upper)
    label.setObjectName("StatusBadge")
    style = BADGE_STYLES.get(upper, BADGE_STYLES["NOT VERIFIED"])
    label.setStyleSheet(style)


class StatusCard(QFrame):
    """Consistent dashboard status card with title, badge, and detail text."""

    def __init__(self, title: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        top = QHBoxLayout()
        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setObjectName("CardTitle")
        self.lbl_badge = QLabel("NOT VERIFIED")
        apply_badge_style(self.lbl_badge, "NOT VERIFIED")
        top.addWidget(self.lbl_title)
        top.addStretch()
        top.addWidget(self.lbl_badge)

        self.lbl_value = QLabel("Checking...")
        self.lbl_value.setObjectName("MetricValue")
        self.lbl_detail = QLabel("")
        self.lbl_detail.setWordWrap(True)
        self.lbl_detail.setStyleSheet("color: #9ca3af; font-size: 12px;")

        layout.addLayout(top)
        layout.addWidget(self.lbl_value)
        layout.addWidget(self.lbl_detail)

    def update_card(self, badge: str, value: str, detail: str = "") -> None:
        apply_badge_style(self.lbl_badge, badge)
        self.lbl_value.setText(value)
        self.lbl_detail.setText(detail)
