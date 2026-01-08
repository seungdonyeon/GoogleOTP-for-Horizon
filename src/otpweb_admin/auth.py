"""Admin auth helpers.

Kept intentionally tiny to minimize behavioral changes.
"""
import config as cfg

# Username for admin login (existing behavior: fixed 'admin' unless you later extend it)
ADMIN_USERNAME = cfg.env_str("ADMIN_USERNAME", "admin").strip() or "admin"
