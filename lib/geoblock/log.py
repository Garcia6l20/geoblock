"""Minimal logging: plain lines on stderr, journald priority prefixes under systemd."""

import os
import sys

_LEVELS = {"error": 3, "warning": 4, "info": 6, "debug": 7}
_threshold = 6


def configure(level: str) -> None:
    global _threshold
    _threshold = _LEVELS[level]


def _emit(level: str, msg: str) -> None:
    prio = _LEVELS[level]
    if prio > _threshold:
        return
    # Collapse control characters so untrusted data can not forge log lines.
    msg = "".join(c if c.isprintable() else "?" for c in msg)
    if os.environ.get("JOURNAL_STREAM"):
        line = f"<{prio}>{msg}"
    elif level in ("error", "warning"):
        line = f"{level}: {msg}"
    else:
        line = msg
    print(line, file=sys.stderr, flush=True)


def error(msg: str) -> None:
    _emit("error", msg)


def warning(msg: str) -> None:
    _emit("warning", msg)


def info(msg: str) -> None:
    _emit("info", msg)


def debug(msg: str) -> None:
    _emit("debug", msg)
