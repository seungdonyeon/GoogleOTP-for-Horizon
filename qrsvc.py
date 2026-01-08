#!/usr/bin/env python3
"""Thin wrapper for Gunicorn.
Keeps the public entrypoint as `qrsvc:app` while moving implementation under src/.
"""
import os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from otpweb_qrsvc.qr_impl import app  # noqa: E402

if __name__ == "__main__":
    host = os.environ.get("QR_BIND", "0.0.0.0")
    port = int(os.environ.get("QR_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
