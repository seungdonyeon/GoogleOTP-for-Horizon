import uuid
from typing import Optional

from flask import g, request as flask_request

# Optional headers that upstream proxies (or the admin UI) can set.
REQ_ID_HEADER = 'X-OTPWEB-REQ-ID'
CLIENT_IP_HEADER = 'X-OTPWEB-CLIENT-IP'


def _uuid_hex() -> str:
    return uuid.uuid4().hex


def get_or_set_req_id(req=None) -> str:
    """Get request id for the current request.

    Priority:
    1) header X-OTPWEB-REQ-ID (if provided)
    2) cached value in flask.g
    3) generated UUID4 hex
    """
    r = req or flask_request
    try:
        hdr = (r.headers.get(REQ_ID_HEADER) or '').strip()
    except Exception:
        hdr = ''
    if hdr:
        g.req_id = hdr
        return hdr

    if getattr(g, 'req_id', None):
        return g.req_id

    rid = _uuid_hex()
    g.req_id = rid
    return rid


def get_client_ip(req=None) -> str:
    """Best-effort client IP detection.

    Priority:
    1) header X-OTPWEB-CLIENT-IP (if admin UI forwards original IP)
    2) first entry of X-Forwarded-For
    3) remote_addr
    """
    r = req or flask_request
    try:
        cip = (r.headers.get(CLIENT_IP_HEADER) or '').strip()
        if cip:
            return cip

        xff = (r.headers.get('X-Forwarded-For') or '').strip()
        if xff:
            return xff.split(',')[0].strip()

        return (getattr(r, 'remote_addr', None) or '').strip() or 'unknown'
    except Exception:
        return 'unknown'


def maybe_set_response_headers(resp, req=None):
    """Attach request id into response headers (non-invasive)."""
    try:
        rid = get_or_set_req_id(req)
        resp.headers.setdefault(REQ_ID_HEADER, rid)
    except Exception:
        pass
    return resp
