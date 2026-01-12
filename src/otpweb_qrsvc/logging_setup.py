"""Logging helpers for otpweb-qr.

- audit: JSON Lines written to audit.log
- app_log: plain text written to qr.log

Directory defaults to /var/log/otpweb (override with OTPWEB_LOG_DIR).
"""

import os

from otpweb_common.structured_logging import StructuredLogger


LOG_DIR = os.environ.get("OTPWEB_LOG_DIR", "/var/log/otpweb")

# Be resilient to older StructuredLogger signatures (some releases used `log_dir`).
try:
    _struct = StructuredLogger(
        app="otpweb",
        component="qr",
        base_dir=LOG_DIR,
        audit_filename="audit.log",
    )
except TypeError:
    _struct = StructuredLogger(
        app="otpweb",
        component="qr",
        log_dir=LOG_DIR,  # type: ignore[arg-type]
        audit_filename="audit.log",
    )

# Prefer the explicit name; keep `audit` for backward compatibility.
audit_logger = _struct
audit = _struct

app_log = _struct.log
