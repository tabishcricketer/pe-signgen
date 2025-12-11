"""Logging configuration for pe-signgen."""
from __future__ import annotations

import logging
import sys
import threading

# Module-level logger
logger = logging.getLogger("pe_signgen")

# Thread-safe print lock for progress output
_print_lock = threading.Lock()


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """
    Configure logging for pe-signgen.
    
    Args:
        verbose: Enable debug output
        quiet: Suppress all output except errors
    """
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "[%(levelname).1s] %(message)s"
    ))
    
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)


def log_info(msg: str) -> None:
    """Log an info message."""
    logger.info(msg)


def log_warning(msg: str) -> None:
    """Log a warning message."""
    logger.warning(msg)


def log_error(msg: str) -> None:
    """Log an error message."""
    logger.error(msg)


def log_debug(msg: str) -> None:
    """Log a debug message."""
    logger.debug(msg)


def print_status(msg: str) -> None:
    """Thread-safe status print to stderr."""
    with _print_lock:
        print(msg, file=sys.stderr, flush=True)
