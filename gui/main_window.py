"""Main Window for ANON-X Privacy Center."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .backend_client import BackendClient
from .dashboard import DashboardPage
from .diagnostics_page import DiagnosticsPage
from .firewall_page import FirewallPage
from .logs_page import LogsPage
from .network_page import NetworkPage
from .notifications import NotificationManager
from .recovery_page import RecoveryPage
from .settings_page import SettingsPage
from .startup_page import StartupPage
from .system_tray import AnonXTrayIcon
from .tor_page import TorPage
from .workers import BackendWorker


class MainWindow(QMainWindow):
    """ANON-X Privacy Center main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ANON-X Privacy Center")
        self.resize(1180, 760)

        icon_path = Path(__file__).resolve().parent / "styles" / "icons" / "anonx.svg"
        self.app_icon = QIcon(str(icon_path)) if icon_path.exists() else QIcon()
        self.setWindowIcon(self.app_icon)

        self.client = BackendClient()
        self._workers: List[BackendWorker] = []
        self._minimize_to_tray = True
        self._force_quit = False
        self._last_overall: str | None = None

        self.tray = AnonXTrayIcon(self.app_icon, self)
        self.tray.act_open.triggered.connect(self._show_from_tray)
        self.tray.act_enable.triggered.connect(lambda: self._run_op("start_protection"))
        self.tray.act_disable.triggered.connect(lambda: self._run_op("stop_protection"))
        self.tray.act_diag.triggered.connect(self._open_diagnostics_and_run)
        self.tray.act_quit.triggered.connect(self._quit_gui_only)
        if AnonXTrayIcon.isSystemTrayAvailable():
            self.tray.show()

        self.notifier = NotificationManager(self.tray, enabled=True)

        # Central layout
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(12, 16, 12, 16)
        sb_layout.setSpacing(6)

        lbl_brand = QLabel("ANON-X")
        lbl_brand.setObjectName("SidebarTitle")
        sb_layout.addWidget(lbl_brand)

        self.stack = QStackedWidget()
        self.page_dash = DashboardPage()
        self.page_net = NetworkPage()
        self.page_diag = DiagnosticsPage()
        self.page_tor = TorPage()
        self.page_fw = FirewallPage()
        self.page_boot = StartupPage()
        self.page_logs = LogsPage()
        self.page_settings = SettingsPage()
        self.page_rec = RecoveryPage()

        pages = [
            ("Dashboard", self.page_dash),
            ("Network Protection", self.page_net),
            ("Privacy Diagnostics", self.page_diag),
            ("Tor & Identity", self.page_tor),
            ("Firewall Center", self.page_fw),
            ("Automatic Protection", self.page_boot),
            ("Logs & Activity", self.page_logs),
            ("Settings", self.page_settings),
            ("Recovery Center", self.page_rec),
        ]

        self.nav_buttons: List[QPushButton] = []
        for idx, (label, widget) in enumerate(pages):
            self.stack.addWidget(widget)
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.clicked.connect(lambda _chk=False, i=idx: self._switch_page(i))
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sb_layout.addStretch()
        self.lbl_op_status = QLabel("Ready")
        self.lbl_op_status.setWordWrap(True)
        self.lbl_op_status.setStyleSheet("color: #9ca3af; font-size: 11px; padding: 6px;")
        sb_layout.addWidget(self.lbl_op_status)

        content_wrap = QWidget()
        cw_layout = QVBoxLayout(content_wrap)
        cw_layout.setContentsMargins(24, 20, 24, 20)
        cw_layout.addWidget(self.stack)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(content_wrap, 1)

        # Connect page signals
        self.page_dash.toggle_requested.connect(
            lambda enable: self._run_op("start_protection" if enable else "stop_protection")
        )
        self.page_net.restart_requested.connect(lambda: self._run_op("restart_protection"))
        self.page_diag.run_diagnostics_requested.connect(lambda: self._run_op("run_diagnostics"))
        self.page_tor.new_identity_requested.connect(lambda: self._run_op("new_identity"))
        self.page_boot.boot_enable_requested.connect(lambda: self._run_op("boot_enable"))
        self.page_boot.boot_disable_requested.connect(lambda: self._run_op("boot_disable"))
        self.page_logs.refresh_requested.connect(
            lambda cat, srch: self._run_op("get_logs", {"category": cat, "search": srch, "limit": 150})
        )
        self.page_settings.save_requested.connect(lambda upd: self._run_op("update_config", {"updates": upd}))
        self.page_settings.reset_requested.connect(lambda: self._run_op("reset_config"))
        self.page_rec.recover_requested.connect(lambda: self._run_op("recover"))

        self._switch_page(0)
        self._run_op("get_status")
        self._run_op("get_config")
        self._run_op("get_logs", {"limit": 100})

        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(lambda: self._run_op("get_status"))
        self.poll_timer.start(4000)

    def _switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", i == index)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _run_op(self, operation: str, payload: Dict[str, Any] | None = None) -> None:
        if operation != "get_status":
            self.lbl_op_status.setText(f"Running: {operation}...")
        worker = BackendWorker(self.client, operation, payload)
        worker.finished_result.connect(self._on_worker_result)
        worker.failed.connect(self._on_worker_error)
        worker.finished.connect(lambda w=worker: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(worker)
        worker.start()

    def _on_worker_result(self, op: str, res: Dict[str, Any]) -> None:
        if op == "get_status" and res.get("ok"):
            st = res["data"]
            self.page_dash.update_status(st)
            self.page_net.update_status(st)
            self.page_tor.update_status(st)
            self.page_fw.update_status(st)
            self.page_boot.update_status(st)
            self.page_rec.update_status(st)
            self.tray.update_state_label(st["overall_state"])

            if self._last_overall is not None and self._last_overall != st["overall_state"]:
                self.notifier.notify("ANON-X Status Changed", f"Protection state is now {st['overall_state']}")
            self._last_overall = st["overall_state"]
            return

        if op == "run_diagnostics" and res.get("ok"):
            self.page_diag.update_report(res["data"])
            self.lbl_op_status.setText("Diagnostics complete.")
            return

        if op == "get_logs" and res.get("ok"):
            self.page_logs.update_logs(res["data"])
            return

        if op in ("get_config", "update_config", "reset_config") and res.get("ok"):
            cfg = res["data"]
            self.page_settings.load_config(cfg)
            self._minimize_to_tray = bool(cfg.get("gui", {}).get("minimize_to_tray", True))
            self.notifier.enabled = bool(cfg.get("gui", {}).get("notifications_enabled", True))
            if op != "get_config":
                self.lbl_op_status.setText(res.get("message", "Settings saved."))
            return

        msg = res.get("message") or res.get("error") or f"{op} finished"
        self.lbl_op_status.setText(msg)
        if not res.get("ok"):
            self.notifier.notify("ANON-X Operation Alert", msg, critical=True)
            QMessageBox.warning(self, "ANON-X", msg)
        else:
            self.notifier.notify("ANON-X", msg)
            self._run_op("get_status")
            self._run_op("get_logs", {"limit": 100})

    def _on_worker_error(self, op: str, err: str) -> None:
        self.lbl_op_status.setText(f"Error ({op}): {err}")

    def _show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _open_diagnostics_and_run(self) -> None:
        self._show_from_tray()
        self._switch_page(2)
        self._run_op("run_diagnostics")

    def _quit_gui_only(self) -> None:
        self._force_quit = True
        QApplication.quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._force_quit and self._minimize_to_tray and self.tray.isVisible():
            event.ignore()
            self.hide()
            self.notifier.notify(
                "ANON-X Minimized",
                "GUI minimized to system tray. Background protection service remains active.",
            )
            return
        super().closeEvent(event)
