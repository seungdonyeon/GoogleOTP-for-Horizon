"""Client helpers for Admin -> QR service calls.

Policy:
  - TLS verification bypass is allowed ONLY for loopback (127.0.0.1 / localhost).
  - For non-loopback targets, default urllib certificate verification applies.
"""
import json
import ssl
import urllib.request
from urllib.parse import urlparse

from typing import Dict, Optional

import config as cfg
from otpweb_common.request_context import REQ_ID_HEADER, CLIENT_IP_HEADER


def _make_request(url: str, extra_headers: Optional[Dict[str, str]] = None) -> urllib.request.Request:
    headers = {
        "Accept": "application/json",
    }
    # Admin -> QR service internal authentication
    try:
        key = (cfg.get_qr_admin_key() or "").strip()  # type: ignore[attr-defined]
    except Exception:
        key = (getattr(cfg, "QR_ADMIN_KEY", "") or "").strip()
    if key:
        headers["X-OTPWEB-ADMIN-KEY"] = key
    if extra_headers:
        headers.update(extra_headers)
    return urllib.request.Request(url, headers=headers)

def _ssl_context_for_url(url: str):
    if cfg.is_loopback_url(url) and cfg.ENABLE_HTTPS:
        # loopback-only exception: allow self-signed without verification
        return ssl._create_unverified_context()
    return None  # default verification

def _get_json(path: str, timeout: int = 5, headers: Optional[Dict[str, str]] = None) -> dict:
    base = cfg.QR_SERVICE_BASE.rstrip("/")
    url = f"{base}{path}"
    ctx = _ssl_context_for_url(url)
    req = _make_request(url, extra_headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        data = resp.read().decode("utf-8", errors="replace")
    return json.loads(data) if data else {}

def qr_get_ttl(timeout: int = 5, req_id: Optional[str] = None, client_ip: Optional[str] = None) -> int:
    headers = {}
    if req_id:
        headers[REQ_ID_HEADER] = req_id
    if client_ip:
        headers[CLIENT_IP_HEADER] = client_ip
    j = _get_json("/get-ttl", timeout=timeout, headers=headers)
    return int(j.get("ttl_sec", j.get("ttl", 3600)))

def qr_get_click_ttl(timeout: int = 5, req_id: Optional[str] = None, client_ip: Optional[str] = None) -> int:
    headers = {}
    if req_id:
        headers[REQ_ID_HEADER] = req_id
    if client_ip:
        headers[CLIENT_IP_HEADER] = client_ip
    j = _get_json("/get-click-ttl", timeout=timeout, headers=headers)
    return int(j.get("click_ttl_sec", j.get("click_ttl", 0)))
