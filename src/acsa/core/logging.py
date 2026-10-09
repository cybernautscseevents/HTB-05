"""Logging setup with secret redaction and structured formatting for ACSA."""

import logging
import re
from typing import Any

# Patterns matching sensitive keys and secrets that must NEVER be logged
SENSITIVE_PATTERNS = [
    (re.compile(r"ghp_[A-Za-z0-9]{36,}", re.IGNORECASE), "***REDACTED***"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{60,}", re.IGNORECASE), "***REDACTED***"),
    (re.compile(r"(bearer\s+)[A-Za-z0-9_\-\.]+", re.IGNORECASE), r"\g<1>***REDACTED***"),
    (
        re.compile(
            r"((?:token|secret|password|api_key|apikey)\s*[:=]\s*['\"]?)([^'\"\s,]+)",
            re.IGNORECASE,
        ),
        r"\g<1>***REDACTED***",
    ),
]


class SecretMaskingFilter(logging.Filter):
    """Logging filter that ensures sensitive tokens and credentials are redacted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.mask_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._sanitize_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._sanitize_value(arg) for arg in record.args)
        return True

    @staticmethod
    def _sanitize_value(val: Any) -> Any:
        if isinstance(val, str):
            return SecretMaskingFilter.mask_secrets(val)
        return val

    @staticmethod
    def mask_secrets(text: str) -> str:
        masked = text
        for pattern, replacement in SENSITIVE_PATTERNS:
            masked = pattern.sub(replacement, masked)
        return masked


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure the root ACSA logger with security filters and clean formatting."""
    logger = logging.getLogger("acsa")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SecretMaskingFilter())
        logger.addHandler(handler)

    logger.propagate = False
    return logger
