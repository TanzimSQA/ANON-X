"""Page 2 — Network Protection & Unsupported Protocol Warnings."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .widgets import StatusCard


class NetworkPage(QWidget):
    restart_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setSpacing(14)

        top = QHBoxLayout()
        title = QLabel("NETWORK PROTECTION")
        title.setObjectName("PageTitle")
        btn_restart = QPushButton("Restart Protection")
        btn_restart.setObjectName("SecondaryButton")
        btn_restart.clicked.connect(self.restart_requested.emit)
        top.addWidget(title)
        top.addStretch()
        top.addWidget(btn_restart)
        root.addLayout(top)

        self.card_routing = StatusCard("Transparent Routing & Interface")
        self.card_dns_nm = StatusCard("DNS & Resolver Integration")
        self.card_v6 = StatusCard("IPv4 / IPv6 Policy")
        root.addWidget(self.card_routing)
        root.addWidget(self.card_dns_nm)
        root.addWidget(self.card_v6)

        warn_box = QFrame()
        warn_box.setObjectName("Card")
        wl = QVBoxLayout(warn_box)
        w_title = QLabel("UNSUPPORTED PROTOCOLS & LIMITATIONS")
        w_title.setObjectName("CardTitle")
        self.lbl_warnings = QLabel("")
        self.lbl_warnings.setWordWrap(True)
        self.lbl_warnings.setStyleSheet("color: #fbbf24;")
        wl.addWidget(w_title)
        wl.addWidget(self.lbl_warnings)
        root.addWidget(warn_box)
        root.addStretch()

    def update_status(self, st: Dict[str, Any]) -> None:
        net = st["network"]
        tor = st["tor"]
        dns = st["dns"]
        v4 = st["ipv4"]
        v6 = st["ipv6"]

        self.card_routing.update_card(
            "ACTIVE" if v4["protected"] else "INACTIVE",
            f"Interface: {net['primary_interface'] or 'None'} | Tor Bootstrap: {tor['bootstrap_percent']}%",
            f"Active Interfaces: {', '.join(net['active_interfaces']) or 'None'} | VM: {net['vm_type'] or 'No'}",
        )
        self.card_dns_nm.update_card(
            "PROTECTED" if dns["protected"] else "NOT VERIFIED",
            f"Nameservers: {', '.join(dns['nameservers']) or 'None'}",
            dns["details"],
        )
        self.card_v6.update_card(
            "PROTECTED" if v6["protected"] else "NOT VERIFIED",
            f"IPv4 Redirect: {v4['tcp_redirect']} | IPv6 Egress Blocked: {v6['egress_blocked']}",
            v6["details"],
        )
        self.lbl_warnings.setText("\n".join(f"• {w}" for w in st.get("warnings", [])))
