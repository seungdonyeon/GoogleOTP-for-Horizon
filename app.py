#!/usr/bin/env python3
import os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from otpweb_admin.app_impl import app

if __name__ == "__main__":
    host = os.environ.get("ADMIN_BIND", "0.0.0.0")
    port = int(os.environ.get("ADMIN_PORT", "8000"))
    app.run(host=host, port=port, debug=False)
