#!/usr/bin/env python3
"""Thin wrapper for Gunicorn and local execution.
Keeps the public entrypoint as `app:app` while moving implementation under src/.
"""
import os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from otpweb_admin.app_impl import app  # noqa: E402

if __name__ == "__main__":
    # Preserve original behavior if executed directly.
    # Prefer running via systemd + gunicorn.
    host = os.environ.get("ADMIN_BIND", "0.0.0.0")
    port = int(os.environ.get("ADMIN_PORT", "8000"))
    app.run(host=host, port=port, debug=False)
