"""Logging helpers for otpweb-admin.

- audit: JSON Lines written to audit.log
- app_log: plain text written to admin.log

Directory defaults to /var/log/otpweb (override with OTPWEB_LOG_DIR).
"""

import os

from otpweb_common.structured_logging import StructuredLogger


LOG_DIR = os.environ.get("OTPWEB_LOG_DIR", "/var/log/otpweb")


def _make_structured_logger() -> StructuredLogger:
    """Build StructuredLogger across versions.

    Some older deployments used a StructuredLogger that accepted
    `log_dir=...` instead of `base_dir=...`. We support both so the
    service doesn't fail to boot with a TypeError.
    """

    try:
        return StructuredLogger(
            app="otpweb",
            component="admin",
            base_dir=LOG_DIR,
            audit_filename="audit.log",
        )
    except TypeError:
        # Backward-compat for older StructuredLogger signature
        return StructuredLogger(
            app="otpweb",
            component="admin",
            log_dir=LOG_DIR,
            audit_filename="audit.log",
        )


_struct = _make_structured_logger()

# Preferred export name (what app_impl.py should import)
audit_logger = _struct

# Backward-compatible export name (some modules imported `audit`)
audit = _struct

# Human-readable app log
app_log = _struct.log
