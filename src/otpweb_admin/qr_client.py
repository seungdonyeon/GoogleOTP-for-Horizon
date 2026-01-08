"""Client helpers for Admin -> QR service calls.

Policy:
  - TLS verification bypass is allowed ONLY for loopback (127.0.0.1 / localhost).
  - For non-loopback targets, default urllib certificate verification applies.
"""
import json
import ssl
import urllib.request
from urllib.parse import urlparse

import config as cfg

def _ssl_context_for_url(url: str):
    if cfg.is_loopback_url(url) and cfg.ENABLE_HTTPS:
        # loopback-only exception: allow self-signed without verification
        return ssl._create_unverified_context()
    return None  # default verification

def _get_json(path: str, timeout: int = 5) -> dict:
    base = cfg.QR_SERVICE_BASE.rstrip("/")
    url = f"{base}{path}"
    ctx = _ssl_context_for_url(url)
    with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
        data = resp.read().decode("utf-8", errors="replace")
    return json.loads(data) if data else {}

def qr_get_ttl(timeout: int = 5) -> int:
    j = _get_json("/get-ttl", timeout=timeout)
    return int(j.get("ttl_sec", j.get("ttl", 3600)))

def qr_get_click_ttl(timeout: int = 5) -> int:
    j = _get_json("/get-click-ttl", timeout=timeout)
    return int(j.get("click_ttl_sec", j.get("click_ttl", 0)))
