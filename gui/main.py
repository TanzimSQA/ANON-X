"""Entry point for ANON-X Privacy Center (`anonx-gui`)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow


def main() -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Warning: Running ANON-X GUI as root is discouraged; prefer normal user with Polkit.", file=sys.stderr)

    app = QApplication(sys.argv)
    app.setApplicationName("ANON-X Privacy Center")
    app.setOrganizationName("ANON-X")

    qss_path = Path(__file__).resolve().parent / "styles" / "dark.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))

    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
