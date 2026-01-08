"""TTL option helpers for templates.

We store TTLs in seconds in the QR service.
Admin UI displays human-friendly labels but posts seconds values.
"""
from typing import List, Tuple

# (label, seconds)
TTL_OPTIONS: List[Tuple[str, int]] = [
    ("5 minutes", 300),
    ("10 minutes", 600),
    ("30 minutes", 1800),
    ("1 hour", 3600),
    ("6 hours", 21600),
    ("24 hours", 86400),
    ("7 days", 604800),
    ("30 days", 2592000),
]

# Click TTL:
# - 0 means "expire immediately AFTER the QR is shown once"
CLICK_TTL_OPTIONS: List[Tuple[str, int]] = [
    ("Ephemeral", 0),
    ("30 seconds", 30),
    ("1 minute", 60),
    ("5 minutes", 300),
    ("10 minutes", 600),
    ("30 minutes", 1800),
]

def ttl_label(ttl_sec: int) -> str:
    ttl_sec = int(ttl_sec)
    for label, sec in TTL_OPTIONS:
        if int(sec) == ttl_sec:
            return label
    return f"{ttl_sec} seconds"

def click_ttl_label(ttl_sec: int) -> str:
    ttl_sec = int(ttl_sec)
    for label, sec in CLICK_TTL_OPTIONS:
        if int(sec) == ttl_sec:
            return label
    return f"{ttl_sec} seconds"
