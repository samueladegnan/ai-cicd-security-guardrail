"""Structured logging configuration for the guardrail.

All modules import ``get_logger`` to obtain a namespaced logger. CLI entry
points call ``configure_logging`` once at startup to set the output format
and level.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(*, level: int = logging.INFO, verbose: bool = False) -> None:
    """Configure root logging for the guardrail CLI.

    Args:
        level: Minimum log level emitted by default.
        verbose: When True, increase the default level to DEBUG and add the
            logger name and line number to each message.
    """
    if verbose:
        level = logging.DEBUG

    fmt = "%(asctime)s %(levelname)s: %(message)s"
    if verbose:
        fmt = "%(asctime)s %(levelname)s [%(name)s:%(lineno)d]: %(message)s"

    logging.basicConfig(
        level=level,
        format=fmt,
        stream=sys.stderr,
    )
    _silence_noisy_loggers()


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger for the given module."""
    return logging.getLogger(name)


def _silence_noisy_loggers() -> None:
    """Raise the effective level of chatty third-party loggers."""
    for logger_name in ("urllib3", "requests", "httpx"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)
