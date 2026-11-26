"""Page 1 — ANON-X Privacy Center Dashboard."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .widgets import StatusCard, apply_badge_style


class DashboardPage(QWidget):
    toggle_requested = Signal(bool)  # True = enable, False = disable

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._is_active = False

        root = QVBoxLayout(self)
        root.setSpacing(16)

        # Header
        header = QHBoxLayout()
        self.lbl_title = QLabel("ANON-X PRIVACY DASHBOARD")
        self.lbl_title.setObjectName("PageTitle")
        self.lbl_meta = QLabel("Version 1.0.0 • Detecting OS...")
        self.lbl_meta.setStyleSheet("color: #9ca3af;")
        header.addWidget(self.lbl_title)
        header.addStretch()
        header.addWidget(self.lbl_meta)
        root.addLayout(header)

        # Hero Card
        hero = QFrame()
        hero.setObjectName("HeroCard")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(24, 20, 24, 20)

        left = QVBoxLayout()
        lbl_hero_t = QLabel("PRIVACY PROTECTION")
        lbl_hero_t.setObjectName("CardTitle")
        self.lbl_hero_badge = QLabel("INACTIVE")
        apply_badge_style(self.lbl_hero_badge, "INACTIVE")
        self.lbl_hero_sub = QLabel(
            "Activate fail-closed nftables protection, Tor TCP/DNS routing, and IPv6 leak blocking."
        )
        self.lbl_hero_sub.setWordWrap(True)
        self.lbl_hero_sub.setStyleSheet("color: #cbd5e1;")
        self.lbl_disclaimer = QLabel(
            "Note: ACTIVE means local routing & firewall rules are verified — not 100% anonymity."
        )
        self.lbl_disclaimer.setStyleSheet("color: #fbbf24; font-size: 11px;")

        left.addWidget(lbl_hero_t)
        left.addWidget(self.lbl_hero_badge)
        left.addWidget(self.lbl_hero_sub)
        left.addWidget(self.lbl_disclaimer)

        self.btn_toggle = QPushButton("ENABLE PRIVACY")
        self.btn_toggle.setObjectName("PrimaryAction")
        self.btn_toggle.setMinimumWidth(210)
        self.btn_toggle.setMinimumHeight(50)
        self.btn_toggle.clicked.connect(lambda: self.toggle_requested.emit(not self._is_active))

        hero_layout.addLayout(left, 1)
        hero_layout.addWidget(self.btn_toggle)
        root.addWidget(hero)

        # 8 Status Cards Grid
        grid = QGridLayout()
        grid.setSpacing(12)
        self.card_tor = StatusCard("1. Tor Protection")
        self.card_dns = StatusCard("2. DNS Protection")
        self.card_ipv4 = StatusCard("3. IPv4 Protection")
        self.card_ipv6 = StatusCard("4. IPv6 Protection")
        self.card_fw = StatusCard("5. Firewall Protection")
        self.card_boot = StatusCard("6. Automatic Startup")
        self.card_rec = StatusCard("7. Recovery System")
        self.card_net = StatusCard("8. Network Status")

        cards = [
            self.card_tor, self.card_dns, self.card_ipv4, self.card_ipv6,
            self.card_fw, self.card_boot, self.card_rec, self.card_net,
        ]
        for idx, card in enumerate(cards):
            grid.addWidget(card, idx // 4, idx % 4)

        root.addLayout(grid)
        root.addStretch()

    def update_status(self, st: Dict[str, Any]) -> None:
        self.lbl_meta.setText(f"v{st['app_version']}  •  {st['os_version']}")
        overall = st["overall_state"]
        self._is_active = overall in ("ACTIVE", "WARNING")
        apply_badge_style(self.lbl_hero_badge, overall)

        if self._is_active:
            self.btn_toggle.setText("DISABLE PRIVACY")
            self.btn_toggle.setObjectName("DangerAction")
        else:
            self.btn_toggle.setText("ENABLE PRIVACY")
            self.btn_toggle.setObjectName("PrimaryAction")
        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

        tor = st["tor"]
        self.card_tor.update_card(
            "ACTIVE" if tor["service_active"] and tor["bootstrap_percent"] >= 100 else ("WARNING" if tor["service_active"] else "INACTIVE"),
            f"Bootstrap {tor['bootstrap_percent']}%",
            tor["bootstrap_summary"],
        )

        dns = st["dns"]
        self.card_dns.update_card(
            "PROTECTED" if dns["protected"] else "NOT VERIFIED",
            "Tor DNSPort" if dns["protected"] else "Unprotected",
            dns["details"],
        )

        v4 = st["ipv4"]
        self.card_ipv4.update_card(
            "PROTECTED" if v4["protected"] else "NOT VERIFIED",
            "TransPort Active" if v4["tcp_redirect"] else "Direct",
            v4["details"],
        )

        v6 = st["ipv6"]
        self.card_ipv6.update_card(
            "PROTECTED" if v6["protected"] else "NOT VERIFIED",
            "Egress Blocked" if v6["egress_blocked"] else "Unblocked",
            v6["details"],
        )

        fw = st["firewall"]
        self.card_fw.update_card(
            "ACTIVE" if fw["filter_active"] else "INACTIVE",
            fw["details"],
            f"Backend: {fw['backend']} | Fail-closed: {fw['fail_closed']}",
        )

        boot = st["startup"]
        self.card_boot.update_card(
            "ENABLED" if boot["enabled"] else "DISABLED",
            "Boot Active" if boot["enabled"] else "Manual Only",
            boot["last_boot_result"] or "No boot check recorded yet",
        )

        rec = st["recovery"]
        self.card_rec.update_card(
            "ACTIVE" if rec["snapshot_available"] else "NOT VERIFIED",
            "Snapshot Ready" if rec["snapshot_available"] else "No Snapshot",
            rec["captured_at"] or "Captured automatically on start",
        )

        net = st["network"]
        self.card_net.update_card(
            "ACTIVE" if net["primary_interface"] else "WARNING",
            net["primary_interface"] or "No Default Route",
            f"NM: {'On' if net['network_manager'] else 'Off'} | Docker: {'On' if net['docker'] else 'Off'}",
        )
