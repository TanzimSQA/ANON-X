"""Page 4 — Tor & Identity Management."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .widgets import StatusCard


class TorPage(QWidget):
    new_identity_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(14)

        top = QHBoxLayout()
        title = QLabel("TOR & IDENTITY")
        title.setObjectName("PageTitle")
        self.btn_newnym = QPushButton("REQUEST NEW TOR CIRCUIT")
        self.btn_newnym.setObjectName("PrimaryAction")
        self.btn_newnym.clicked.connect(self.new_identity_requested.emit)
        top.addWidget(title)
        top.addStretch()
        top.addWidget(self.btn_newnym)
        root.addLayout(top)

        self.card_tor = StatusCard("Tor Daemon & ControlPort")
        root.addWidget(self.card_tor)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        root.addWidget(self.progress)

        lbl_circ = QLabel("BUILT CIRCUITS (LOCAL CONTROLPORT)")
        lbl_circ.setObjectName("CardTitle")
        root.addWidget(lbl_circ)

        self.txt_circuits = QPlainTextEdit()
        self.txt_circuits.setReadOnly(True)
        root.addWidget(self.txt_circuits)

        guidance = QFrame()
        guidance.setObjectName("Card")
        gl = QVBoxLayout(guidance)
        g_t = QLabel("TOR BROWSER & IDENTITY GUIDANCE")
        g_t.setObjectName("CardTitle")
        g_body = QLabel(
            "• Requesting a new Tor circuit (SIGNAL NEWNYM) builds fresh circuits for new connections, "
            "but does not guarantee a different exit IP or reset browser cookies/fingerprinting.\n"
            "• Prefer Tor Browser over standard browsers to resist WebRTC leaks and fingerprinting.\n"
            "• Avoid logging into personal accounts or torrenting over Tor."
        )
        g_body.setWordWrap(True)
        g_body.setStyleSheet("color: #cbd5e1;")
        gl.addWidget(g_t)
        gl.addWidget(g_body)
        root.addWidget(guidance)

    def update_status(self, st: Dict[str, Any]) -> None:
        tor = st["tor"]
        self.progress.setValue(int(tor["bootstrap_percent"]))
        self.card_tor.update_card(
            "ACTIVE" if tor["service_active"] and tor["bootstrap_percent"] >= 100 else ("WARNING" if tor["service_active"] else "INACTIVE"),
            f"Bootstrap: {tor['bootstrap_percent']}% | ControlPort Cookie Auth: {'Verified' if tor['control_authenticated'] else 'Unavailable'}",
            tor["bootstrap_summary"],
        )
        circuits = tor.get("circuits") or []
        self.txt_circuits.setPlainText("\n".join(circuits) if circuits else "No built circuits reported or ControlPort unavailable.")
