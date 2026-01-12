import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence

import config as cfg


def _now_iso() -> str:
    # ISO 8601 with timezone offset
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_makedirs(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        return False


def _default_log_dir() -> str:
    # Prefer /var/log/otpweb (root-run services). Fall back to project-local logs.
    return getattr(cfg, "OTPWEB_LOG_DIR", "") or "/var/log/otpweb"


def _get_log_dir() -> str:
    d = (os.environ.get("OTPWEB_LOG_DIR") or getattr(cfg, "OTPWEB_LOG_DIR", "") or "").strip()
    if not d:
        d = _default_log_dir()
    if _safe_makedirs(d):
        return d
    # fall back: project-local
    d2 = os.path.join(cfg.PROJECT_ROOT, "logs")
    _safe_makedirs(d2)
    return d2


def _get_level() -> int:
    s = (os.environ.get("OTPWEB_LOG_LEVEL") or getattr(cfg, "OTPWEB_LOG_LEVEL", "") or "INFO").strip().upper()
    return getattr(logging, s, logging.INFO)


def _retention_months() -> int:
    s = (os.environ.get("OTPWEB_LOG_RETENTION_MONTHS") or getattr(cfg, "OTPWEB_LOG_RETENTION_MONTHS", "") or "12").strip()
    try:
        v = int(s)
        return max(1, min(v, 120))
    except Exception:
        return 12


@dataclass
class MonthlyRotator:
    path: str
    retention_months: int = 12

    def _month_tag(self, ts: Optional[float] = None) -> str:
        dt = datetime.fromtimestamp(ts or time.time()).astimezone()
        return dt.strftime("%Y-%m")

    def _rotate_if_needed(self) -> None:
        # Rotate when current month differs from file mtime month
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        except Exception:
            return

        file_month = self._month_tag(st.st_mtime)
        now_month = self._month_tag()
        if file_month == now_month:
            return

        bak = f"{self.path}.{file_month}.bak"
        try:
            if not os.path.exists(bak):
                os.rename(self.path, bak)
        except Exception:
            # In multi-worker deployments, another process may rotate concurrently.
            pass

        self._cleanup_old()

    def _cleanup_old(self) -> None:
        # Keep at most N months of .bak files
        base = os.path.basename(self.path)
        parent = os.path.dirname(self.path) or "."
        try:
            files = []
            for fn in os.listdir(parent):
                if not fn.startswith(base + ".") or not fn.endswith(".bak"):
                    continue
                # expect base.YYYY-MM.bak
                parts = fn.split(".")
                if len(parts) < 3:
                    continue
                tag = parts[-2]  # YYYY-MM
                files.append((tag, os.path.join(parent, fn)))
            files.sort(key=lambda x: x[0], reverse=True)
            for i, (_, fp) in enumerate(files):
                if i >= self.retention_months:
                    try:
                        os.remove(fp)
                    except Exception:
                        pass
        except Exception:
            pass

    def append_line(self, line: str) -> None:
        # Best-effort; never raise to caller.
        try:
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
                if not line.endswith("\n"):
                    f.write("\n")
        except Exception:
            # last resort: stdout
            try:
                sys.stdout.write(line + ("\n" if not line.endswith("\n") else ""))
            except Exception:
                pass


class MonthlyFileHandler(logging.Handler):
    def __init__(self, path: str, retention_months: int = 12):
        super().__init__()
        self.rot = MonthlyRotator(path=path, retention_months=retention_months)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        self.rot.append_line(msg)


_LOGGERS: Dict[str, logging.Logger] = {}
_AUDIT_WRITER: Optional[MonthlyRotator] = None


def get_logger(component: str) -> logging.Logger:
    """
    component: e.g. "admin", "qr"
    Writes to:
      - <log_dir>/<component>.log  (monthly .bak rotation)
      - stdout (journald), same format
    """
    component = (component or "app").strip().lower()
    if component in _LOGGERS:
        return _LOGGERS[component]

    log_dir = _get_log_dir()
    level = _get_level()
    retention = _retention_months()

    logger = logging.getLogger(f"otpweb.{component}")
    logger.setLevel(level)
    logger.propagate = False

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s component=%(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # File
    fh = MonthlyFileHandler(os.path.join(log_dir, f"{component}.log"), retention_months=retention)
    fh.setLevel(level)
    fh.setFormatter(fmt)

    # Stdout (journald)
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(level)
    sh.setFormatter(fmt)

    # Avoid duplicate handlers if reloaded
    logger.handlers = []
    logger.addHandler(fh)
    logger.addHandler(sh)

    _LOGGERS[component] = logger
    return logger


def _audit_writer() -> MonthlyRotator:
    global _AUDIT_WRITER
    if _AUDIT_WRITER is not None:
        return _AUDIT_WRITER
    log_dir = _get_log_dir()
    retention = _retention_months()
    _AUDIT_WRITER = MonthlyRotator(path=os.path.join(log_dir, "audit.log"), retention_months=retention)
    return _AUDIT_WRITER


def audit_event(
    *,
    component: str,
    event: str,
    actor: str = "admin",
    targets: Optional[Sequence[str]] = None,
    result: str = "ok",
    reason: Optional[str] = None,
    ip: Optional[str] = None,
    req: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Structured audit event (JSONL). Syslog-friendly fields included.
    """
    payload: Dict[str, Any] = {
        "ts": _now_iso(),
        "app": "otpweb",
        "component": component,
        "event": event,
        "actor": actor,
        "targets": list(targets) if targets else [],
        "result": result,
    }
    if reason:
        payload["reason"] = str(reason)[:500]
    if ip:
        payload["ip"] = ip
    if req:
        payload["req"] = req
    if extra:
        # Keep extra nested to avoid uncontrolled field explosion
        payload["extra"] = extra

    try:
        _audit_writer().append_line(json.dumps(payload, ensure_ascii=False))
    except Exception:
        # never raise
        pass


def audit_error(
    *,
    component: str,
    event: str,
    actor: str = "admin",
    targets: Optional[Sequence[str]] = None,
    ip: Optional[str] = None,
    req: Optional[str] = None,
    err: Optional[BaseException] = None,
    reason: Optional[str] = None,
) -> None:
    r = reason or (repr(err) if err else "error")
    audit_event(component=component, event=event, actor=actor, targets=targets, result="fail", reason=r, ip=ip, req=req)
