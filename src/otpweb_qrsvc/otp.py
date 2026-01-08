import urllib.parse
import config as cfg

def display_name() -> str:
    dn = cfg.env_str("OTP_DISPLAY_NAME", "").strip()
    if dn:
        return dn
    # Backward-compatible fallback
    legacy = cfg.env_str("OTP_LABEL_PREFIX", "").strip() or cfg.env_str("OTP_ISSUER", "").strip()
    return legacy or "VDI"

def build_otpauth(user: str, secret: str) -> str:
    dn = display_name()
    label = f"{dn}:{user}"
    label_q = urllib.parse.quote(label, safe="")
    issuer_q = urllib.parse.quote(dn, safe="")
    return f"otpauth://totp/{label_q}?secret={secret}&issuer={issuer_q}"
