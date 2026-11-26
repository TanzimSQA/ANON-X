"""Page 7 — Sanitized Logs & Activity Viewer."""

from __future__ import annotations

from typing import List

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class LogsPage(QWidget):
    refresh_requested = Signal(str, str)  # category, search

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(12)

        top = QHBoxLayout()
        title = QLabel("LOGS & ACTIVITY (SANITIZED)")
        title.setObjectName("PageTitle")
        top.addWidget(title)
        top.addStretch()

        self.cmb_cat = QComboBox()
        self.cmb_cat.addItems(["ALL", "TOR", "FIREWALL", "RECOVERY", "STARTUP", "SERVICE"])
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Filter logs...")
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setObjectName("SecondaryButton")
        btn_refresh.clicked.connect(self._emit_refresh)
        btn_export = QPushButton("Export")
        btn_export.setObjectName("SecondaryButton")
        btn_export.clicked.connect(self._export_logs)

        top.addWidget(self.cmb_cat)
        top.addWidget(self.txt_search)
        top.addWidget(btn_refresh)
        top.addWidget(btn_export)
        root.addLayout(top)

        self.txt_logs = QPlainTextEdit()
        self.txt_logs.setReadOnly(True)
        root.addWidget(self.txt_logs)

    def _emit_refresh(self) -> None:
        self.refresh_requested.emit(self.cmb_cat.currentText(), self.txt_search.text())

    def update_logs(self, lines: List[str]) -> None:
        self.txt_logs.setPlainText("\n".join(lines) if lines else "No sanitized log entries available.")

    def _export_logs(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Sanitized Logs", "anonx_logs.txt", "Text (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.txt_logs.toPlainText())
