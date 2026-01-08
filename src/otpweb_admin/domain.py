"""Domain/realm helper (best-effort).

Used only for display/diagnostics in the Admin UI.
"""
import subprocess

def get_joined_domain() -> str:
    # Try 'realm list' (SSSD/realmd environments) first
    try:
        out = subprocess.check_output(["realm", "list"], stderr=subprocess.DEVNULL, text=True, timeout=2)
        for line in out.splitlines():
            line=line.strip()
            if line and not line.startswith("#") and ":" not in line:
                # some outputs start with the realm name
                return line
        # fallback: look for 'realm-name:' style
        for line in out.splitlines():
            if "realm-name:" in line.lower():
                return line.split(":",1)[1].strip()
    except Exception:
        pass

    # Try winbind / net ads info
    try:
        out = subprocess.check_output(["net", "ads", "info"], stderr=subprocess.DEVNULL, text=True, timeout=2)
        for line in out.splitlines():
            if ":" in line:
                k,v=line.split(":",1)
                if k.strip().lower() in ("realm", "domain"):
                    return v.strip()
    except Exception:
        pass

    return ""
