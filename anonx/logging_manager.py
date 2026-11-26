"""Structured logging and log sanitization for ANON-X."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List

DEFAULT_LOG_DIR = Path("/var/log/anonx")
DEFAULT_LOG_FILE = "anonx.log"

_REDACT_PATTERNS = [
    (re.compile(r"(cookie[_-]?auth(?:file)?\s*[:=]\s*)(\S+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(AUTHENTICATE\s+)([0-9a-fA-F\"']+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(password\s*[:=]\s*)(\S+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*[:=]\s*)(\S+)", re.IGNORECASE), r"\1[REDACTED]"),
]


def sanitize_log_line(line: str) -> str:
    """Remove potential secrets, control cookies, and credentials from log text."""
    sanitized = line
    for pattern, repl in _REDACT_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    return sanitized


class SanitizingFormatter(logging.Formatter):
    """Formatter that redacts sensitive fields before writing."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return sanitize_log_line(formatted)


class LoggingManager:
    """Configures rotating structured logs and provides sanitized log retrieval."""

    def __init__(self, log_dir: Path | str = DEFAULT_LOG_DIR, level: str = "INFO") -> None:
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / DEFAULT_LOG_FILE
        self.level = getattr(logging, level.upper(), logging.INFO)
        self.logger = self._configure_logger()

    def _configure_logger(self) -> logging.Logger:
        logger = logging.getLogger("anonx")
        logger.setLevel(self.level)
        if logger.handlers:
            return logger

        fmt = SanitizingFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                self.log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except OSError:
            # Non-root or read-only environment fallback to stream handler only
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(fmt)
            logger.addHandler(stream_handler)

        return logger

    def read_recent(self, limit: int = 100, category: str | None = None, search: str | None = None) -> List[str]:
        """Return sanitized recent log lines with optional category and substring filter."""
        if not self.log_file.exists():
            return []
        lines = self.log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        results: List[str] = []
        cat_upper = category.upper() if category else None
        search_lower = search.lower() if search else None

        for raw in reversed(lines):
            clean = sanitize_log_line(raw)
            if cat_upper and cat_upper != "ALL" and cat_upper not in clean.upper():
                continue
            if search_lower and search_lower not in clean.lower():
                continue
            results.append(clean)
            if len(results) >= limit:
                break
        return list(reversed(results))
