from flask import Flask, request, abort, send_file, jsonify, make_response, redirect
import io, time
import config as cfg

from . import db_layer, settings, tokens as token_mod, otp as otp_mod, qr_image

# Keep env-driven bind/port for compatibility (gunicorn supplies bind anyway)
APP_HOST = cfg.env_str('QR_BIND', '0.0.0.0')
APP_PORT = cfg.env_int('QR_PORT', 5000)

DEFAULT_TTL_SEC = settings.DEFAULT_TTL_SEC
DEFAULT_CLICK_TTL_SEC = settings.DEFAULT_CLICK_TTL_SEC

app = Flask(__name__)
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
    key = (getattr(cfg, "QR_ADMIN_KEY", "") or "").strip()
    if not key:
        return
    got = (request.headers.get('X-OTPWEB-ADMIN-KEY') or "").strip()
    if got != key:
        abort(403, 'admin key required')

def is_preview_bot(ua: str) -> bool:
    ua = (ua or "").lower()
    return any(x in ua for x in ("slackbot", "teams", "msteams", "facebookexternalhit", "discordbot", "telegrambot", "whatsapp", "preview", "linkpreview"))

def no_cache(resp):
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

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

    # Re-fetch row to observe used changes
    row = token_mod.get_row(token)
    if (not row) or row['used']==1 or token_mod.is_creation_expired(row) or token_mod.is_click_window_expired(row):
        return respond_expired()

    user = row['user']
    secret = row['secret']
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
    return jsonify({"ok": True, "click_ttl_sec": val})

@app.post('/purge')
def purge():
    require_admin()
    token_mod.purge()
    return jsonify({"ok": True})

if __name__ == '__main__':
    # Dev only; in production, gunicorn is used via systemd.
    app.run(host=APP_HOST, port=APP_PORT, debug=False)