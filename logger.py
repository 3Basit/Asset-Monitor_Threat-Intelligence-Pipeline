"""
logger.py — Structured Logging Setup
======================================
Provides a get_logger() factory that all modules use.
Supports console + optional file output with rotation.
"""

import logging
import logging.handlers
import config


_initialized = False


def _setup_root():
    global _initialized
    if _initialized:
        return
    _initialized = True

    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    if not root.handlers:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(config.LOG_FORMAT))
        root.addHandler(console)

        if config.LOG_FILE:
            file_handler = logging.handlers.RotatingFileHandler(
                config.LOG_FILE, maxBytes=10_000_000, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
            root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    _setup_root()
    return logging.getLogger(name)
