import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _month_stamp(t: Optional[float] = None) -> str:
    lt = time.localtime(t or time.time())
    return f"{lt.tm_year:04d}{lt.tm_mon:02d}"


def _rotate_monthly(path: str) -> None:
    """Rotate the file if its mtime month differs from now.

    This keeps behavior predictable without external logrotate.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    except Exception:
        return

    old = _month_stamp(st.st_mtime)
    cur = _month_stamp()
    if old == cur:
        return

    rotated = f"{path}.{old}.bak"
    try:
        os.replace(path, rotated)
    except FileNotFoundError:
        return
    except Exception:
        # Best-effort only.
        return


@dataclass
class StructuredLogger:
    """Simple structured logger writing (1) audit.jsonl and (2) component.log."""

    app: str
    component: str
    base_dir: str = '/var/log/otpweb'

    audit_filename: str = 'audit.log'

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        _ensure_dir(self.base_dir)
        self.audit_path = os.path.join(self.base_dir, self.audit_filename)
        self.component_path = os.path.join(self.base_dir, f"{self.component}.log")

    def _write_line(self, path: str, line: str) -> None:
        _rotate_monthly(path)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line)
            if not line.endswith('\n'):
                f.write('\n')

    def audit(self, event: str, *, actor: str, result: str = 'ok', ip: str = '-', req: str = '-',
              targets=None, reason: Optional[str] = None, **extra: Any) -> None:
        """Write an audit event as JSON lines."""
        payload: Dict[str, Any] = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime()),
            'app': self.app,
            'component': self.component,
            'event': event,
            'actor': actor,
            'targets': targets or [],
            'result': result,
            'ip': ip,
            'req': req,
        }
        if reason:
            payload['reason'] = reason
        payload.update(extra)

        with self._lock:
            self._write_line(self.audit_path, json.dumps(payload, ensure_ascii=False))

    def log(self, level: str, message: str, *, ip: str = '-', req: str = '-', **fields: Any) -> None:
        """Write a human-friendly single line log for the component."""
        parts = [
            time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime()),
            level.upper(),
            f"component={self.app}.{self.component}",
        ]
        if ip:
            parts.append(f"ip={ip}")
        if req:
            parts.append(f"req={req}")
        if fields:
            for k, v in fields.items():
                parts.append(f"{k}={v}")
        parts.append(message)
        line = ' '.join(str(p) for p in parts)
        with self._lock:
            self._write_line(self.component_path, line)
