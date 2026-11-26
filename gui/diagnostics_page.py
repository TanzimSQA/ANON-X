"""Page 3 — Privacy Diagnostics Table & Sanitized Report Export."""

from __future__ import annotations

import json
from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class DiagnosticsPage(QWidget):
    run_diagnostics_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._last_report: Dict[str, Any] = {}

        root = QVBoxLayout(self)
        root.setSpacing(12)

        top = QHBoxLayout()
        title = QLabel("PRIVACY DIAGNOSTICS")
        title.setObjectName("PageTitle")
        self.btn_run = QPushButton("RUN FULL DIAGNOSTIC")
        self.btn_run.setObjectName("PrimaryAction")
        self.btn_run.clicked.connect(self.run_diagnostics_requested.emit)
        self.btn_export = QPushButton("Export Report")
        self.btn_export.setObjectName("SecondaryButton")
        self.btn_export.clicked.connect(self._export_report)

        top.addWidget(title)
        top.addStretch()
        top.addWidget(self.btn_export)
        top.addWidget(self.btn_run)
        root.addLayout(top)

        self.lbl_summary = QLabel("Click 'RUN FULL DIAGNOSTIC' to inspect Tor, nftables, DNS, IPv4/IPv6, and startup state.")
        self.lbl_summary.setStyleSheet("color: #9ca3af;")
        root.addWidget(self.lbl_summary)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["CHECK", "STATUS", "DETAILS"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        root.addWidget(self.table)

    def update_report(self, report: Dict[str, Any]) -> None:
        self._last_report = report
        checks = report.get("checks", [])
        self.table.setRowCount(len(checks))
        for row, item in enumerate(checks):
            self.table.setItem(row, 0, QTableWidgetItem(item["check"]))
            st_item = QTableWidgetItem(item["status"])
            self.table.setItem(row, 1, st_item)
            self.table.setItem(row, 2, QTableWidgetItem(item["details"]))

        s = report.get("summary", {})
        self.lbl_summary.setText(
            f"Completed at {report.get('timestamp', '')}  |  "
            f"PASS: {s.get('PASS', 0)}  WARNING: {s.get('WARNING', 0)}  "
            f"FAILED: {s.get('FAILED', 0)}  NOT SUPPORTED: {s.get('NOT SUPPORTED', 0)}"
        )

    def _export_report(self) -> None:
        if not self._last_report:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Sanitized Diagnostic Report", "anonx_diagnostics.json", "JSON (*.json)")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self._last_report, handle, indent=2)
