from flask import Flask, request, abort, send_file, jsonify, make_response, redirect
import io, time
import config as cfg

from werkzeug.exceptions import HTTPException
from otpweb_qrsvc.logging_setup import audit_logger, app_log
from otpweb_common.request_context import get_or_set_req_id, get_client_ip

from . import db_layer, settings, tokens as token_mod, otp as otp_mod, qr_image

# Keep env-driven bind/port for compatibility (gunicorn supplies bind anyway)
APP_HOST = cfg.env_str('QR_BIND', '0.0.0.0')
APP_PORT = cfg.env_int('QR_PORT', 5000)

DEFAULT_TTL_SEC = settings.DEFAULT_TTL_SEC
DEFAULT_CLICK_TTL_SEC = settings.DEFAULT_CLICK_TTL_SEC

app = Flask(__name__)


@app.before_request
def _set_request_context():
    get_or_set_req_id()
db_layer.init_db(DEFAULT_TTL_SEC, DEFAULT_CLICK_TTL_SEC)

def require_admin():
    """Protect admin-only endpoints.

    The QR service is typically reachable by end-users (to fetch /q/<token> images).
    However, endpoints that create tokens or mutate QR service state MUST be
    restricted to the Admin UI.

    Policy:
      - If QR_ADMIN_KEY is set, requests must include the header:
          X-OTPWEB-ADMIN-KEY: <QR_ADMIN_KEY>
      - If QR_ADMIN_KEY is empty, allow the request (backward compatibility).
        (Installer should generate/set QR_ADMIN_KEY for secure deployments.)
    """
    # Compatibility: some installs only set ADMIN_KEY.
    key = (getattr(cfg, "QR_ADMIN_KEY", "") or getattr(cfg, "ADMIN_KEY", "") or "").strip()
    if not key:
        return
    # Accept multiple ways of sending the admin key for compatibility:
    #  - X-OTPWEB-ADMIN-KEY: <key>
    #  - Authorization: Bearer <key>
    #  - admin_key query param
    #  - admin_key in JSON/form body
    got = (request.headers.get('X-OTPWEB-ADMIN-KEY') or "").strip()
    if not got:
        authz = (request.headers.get('Authorization') or '').strip()
        if authz.lower().startswith('bearer '):
            got = authz.split(None, 1)[1].strip()
    if not got:
        got = (request.args.get('admin_key') or '').strip()
    if not got and request.is_json:
        data = request.get_json(silent=True) or {}
        got = (str(data.get('admin_key') or '')).strip()
    if not got and request.form:
        got = (request.form.get('admin_key') or '').strip()

    if got != key:
        audit_logger.audit(
            event='qr_admin_auth',
            actor='admin',
            result='fail',
            reason='admin_key_required' if not got else 'invalid_admin_key',
            ip=get_client_ip(),
            req=get_or_set_req_id(),
            path=request.path,
            method=request.method,
        )
        abort(403, 'admin key required')


@app.errorhandler(HTTPException)
def _handle_http_exception(e: HTTPException):
    # Avoid "unhandled exception" stacks for expected 4xx responses.
    # We still return a clear JSON payload for API callers.
    return jsonify({
        'ok': False,
        'error': e.name,
        'message': e.description,
    }), e.code

def is_preview_bot(ua: str) -> bool:
    ua = (ua or "").lower()
    return any(x in ua for x in ("slackbot", "teams", "msteams", "facebookexternalhit", "discordbot", "telegrambot", "whatsapp", "preview", "linkpreview"))

def no_cache(resp):
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


def remaining_windows(row):
    """Compute remaining seconds for creation TTL and click TTL.

    Returns (ttl_remain, click_remain) where each is:
      - None when the corresponding TTL is 'infinite' (configured 0 for creation, 0 for click-after-view semantics treated specially)
      - 0 or positive int otherwise (clamped at 0)
    """
    now = int(time.time())
    ttl = settings.get_ttl_sec()
    click_ttl = settings.get_click_ttl_sec()

    ttl_remain = None
    if ttl > 0:
        ttl_remain = max(0, int(ttl) - (now - int(row["created_at"])))

    click_remain = None
    ca = row["clicked_at"]
    if ca is not None:
        if click_ttl > 0:
            click_remain = max(0, int(click_ttl) - (now - int(ca)))
        elif click_ttl == 0:
            # Special semantics: expire immediately AFTER QR shown once.
            click_remain = 0
    return ttl_remain, click_remain

def respond_expired():
    html = """<!doctype html>
<meta charset="utf-8">
<meta name="robots" content="noindex,noimageindex,noarchive,nofollow">
<meta name="referrer" content="no-referrer">
<title>Expired</title>
<div style="font-family:sans-serif;padding:24px">
  <h3>QR link expired</h3>
  <p>Please request a new OTP QR link from your administrator.</p>
</div>"""
    resp = make_response(html, 410)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return no_cache(resp)

@app.post('/token')
def create_token():
    require_admin()
    # Accept both form and JSON (backward compatible)
    user = ""
    ttl_override = None
    click_override = None

    if request.is_json:
        data = request.get_json(silent=True) or {}
        user = (data.get("user") or "").strip()
        if "ttl_sec" in data:
            ttl_override = data.get("ttl_sec")
        if "click_ttl_sec" in data:
            click_override = data.get("click_ttl_sec")
    else:
        user = (request.form.get('user','') or "").strip()

    if not user:
        abort(400, 'user required')

    try:
        info = token_mod.create_token(
            user,
            ttl_sec=(int(ttl_override) if ttl_override is not None else None),
            click_ttl_sec=(int(click_override) if click_override is not None else None),
        )
    except FileNotFoundError:
        abort(404, 'secret not found for user')
    except ValueError:
        abort(400, 'user required')

    resp = jsonify({"url": info["url"], "absolute_url": info["absolute_url"], "expires_in_sec": info["expires_in_sec"]})
    # Human-friendly app log (qr.log). Do NOT log secrets or full URLs.
    try:
        app_log(
            'INFO',
            'token issued',
            ip=get_client_ip(),
            req=get_or_set_req_id(),
            user=user,
            ttl_sec=info.get('expires_in_sec'),
        )
    except Exception:
        pass
    return no_cache(resp)

@app.get('/q/<token>')
def q_landing(token):
    if request.method == 'HEAD' or is_preview_bot(request.headers.get('User-Agent','')):
        return no_cache(make_response('', 204))
    row = token_mod.get_row(token)
    if (not row) or row['used']==1 or token_mod.is_creation_expired(row) or token_mod.is_click_window_expired(row):
        return respond_expired()
    html = f"""<!doctype html>
<meta charset="utf-8">
<meta name="robots" content="noindex,noimageindex,noarchive,nofollow">
<meta name="referrer" content="no-referrer">
<title>Open QR Code</title>
<div style="display:flex;min-height:60vh;align-items:center;justify-content:center;">
  <form method="post" action="/q/{token}/open" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
    <span style="font-family:sans-serif">To view the QR code, click the button below.</span>
    <button type="submit" style="padding:10px 16px;border:1px solid #ccc;border-radius:8px;cursor:pointer;background:#eee;">
      View QR
    </button>
  </form>
</div>"""
    resp = make_response(html,200)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return no_cache(resp)

@app.get('/q/<token>/open')
def q_open_get(token):
    row = token_mod.get_row(token)
    if (not row) or row['used']==1 or token_mod.is_creation_expired(row) or token_mod.is_click_window_expired(row):
        return respond_expired()
    return no_cache(redirect(f"/q/{token}", code=303))

@app.post('/q/<token>/open')
def q_open_post(token):
    row = token_mod.get_row(token)
    if (not row) or row['used']==1 or token_mod.is_creation_expired(row) or token_mod.is_click_window_expired(row):
        return respond_expired()

    # record click (and possibly mark used immediately if click_ttl==0)
    token_mod.record_click(token)

    # Log a successful view (helps trace why/when a link was consumed).
    try:
        app_log(
            'INFO',
            'token viewed',
            ip=get_client_ip(),
            req=get_or_set_req_id(),
            token=token,
            click_ttl_sec=settings.get_click_ttl_sec(),
            click_remain_sec=click_remain,
            ttl_remain_sec=ttl_remain,
        )
    except Exception:
        pass

    # Re-fetch row to observe used changes
    row = token_mod.get_row(token)
    if (not row) or row['used']==1 or token_mod.is_creation_expired(row) or token_mod.is_click_window_expired(row):
        return respond_expired()

    user = row['user']
    secret = row['secret']
    # Compute remaining windows for logging
    ttl_remain, click_remain = (None, None)
    try:
        ttl_remain, click_remain = remaining_windows(row)
    except Exception:
        pass

    # App log for operations visibility.
    try:
        app_log(
            'INFO',
            'qr viewed',
            ip=get_client_ip(),
            req=get_or_set_req_id(),
            user=user,
            ttl_sec=settings.get_ttl_sec(),
            ttl_remain_sec=ttl_remain,
            click_ttl_sec=settings.get_click_ttl_sec(),
            click_remain_sec=click_remain,
        )
    except Exception:
        pass
    otpauth = otp_mod.build_otpauth(user, secret)
    png = qr_image.png_bytes(otpauth)
    buf = io.BytesIO(png)
    resp = send_file(buf, mimetype='image/png', as_attachment=False, download_name=f"{user}_otp.png")
    # If click TTL is 0, expire immediately AFTER this successful view.
    try:
        if settings.get_click_ttl_sec() == 0:
            token_mod.mark_used(token)
    except Exception:
        pass
    return no_cache(resp)

@app.post('/mark-used')
def mark_used():
    require_admin()
    token = (request.form.get('token','') or '').strip()
    if not token:
        abort(400, 'token required')
    token_mod.mark_used(token)
    return jsonify({"ok": True})

@app.get('/get-ttl')
def get_ttl():
    require_admin()
    return jsonify({"ttl_sec": settings.get_ttl_sec()})

@app.post('/set-ttl')
def set_ttl():
    require_admin()
    ttl_sec = request.form.get('ttl_sec')
    if request.is_json:
        data = request.get_json(silent=True) or {}
        ttl_sec = data.get('ttl_sec', ttl_sec)
    if ttl_sec is None:
        abort(400, 'ttl_sec required')
    val = int(ttl_sec)
    settings.set_ttl_sec(val)
    try:
        app_log('INFO', 'ttl updated', ip=get_client_ip(), req=get_or_set_req_id(), ttl_sec=val)
    except Exception:
        pass
    return jsonify({"ok": True, "ttl_sec": val})
@app.get('/get-click-ttl')
def get_click_ttl():
    require_admin()
    return jsonify({"click_ttl_sec": settings.get_click_ttl_sec()})

@app.post('/set-click-ttl')
def set_click_ttl():
    require_admin()
    click_ttl_sec = request.form.get('click_ttl_sec')
    if request.is_json:
        data = request.get_json(silent=True) or {}
        click_ttl_sec = data.get('click_ttl_sec', click_ttl_sec)
    if click_ttl_sec is None:
        abort(400, 'click_ttl_sec required')
    val = int(click_ttl_sec)
    settings.set_click_ttl_sec(val)
    try:
        app_log('INFO', 'click_ttl updated', ip=get_client_ip(), req=get_or_set_req_id(), click_ttl_sec=val)
    except Exception:
        pass
    return jsonify({"ok": True, "click_ttl_sec": val})

@app.post('/purge')
def purge():
    require_admin()
    token_mod.purge()
    return jsonify({"ok": True})

if __name__ == '__main__':
    # Dev only; in production, gunicorn is used via systemd.
    app.run(host=APP_HOST, port=APP_PORT, debug=False)