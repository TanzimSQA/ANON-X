"""Asynchronous Qt workers so backend operations never freeze the GUI."""

from __future__ import annotations

from typing import Any, Dict

from PySide6.QtCore import QThread, Signal

from .backend_client import BackendClient


class BackendWorker(QThread):
    """Executes a backend operation on a background thread."""

    finished_result = Signal(str, dict)
    failed = Signal(str, str)

    def __init__(self, client: BackendClient, operation: str, payload: Dict[str, Any] | None = None) -> None:
        super().__init__()
        self.client = client
        self.operation = operation
        self.payload = payload or {}

    def run(self) -> None:
        try:
            res = self.client.call(self.operation, self.payload)
            self.finished_result.emit(self.operation, res)
        except Exception as exc:
            self.failed.emit(self.operation, str(exc))
