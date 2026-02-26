"""JSON structured logger for scan events (useful for RL replay)."""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "scan_data"):
            log_entry["scan_data"] = record.scan_data
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry)


def setup_logger(
    name: str = "network_scanner",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    json_format: bool = True,
) -> logging.Logger:
    """Configure and return a logger instance.

    Args:
        name: Logger name.
        level: Logging level.
        log_file: Optional file path for log output.
        json_format: If True, use JSON formatting.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter: logging.Formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "network_scanner") -> logging.Logger:
    """Get an existing logger or create one with defaults."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger
