"""Thin wrapper around systemctl limited to the units this project owns."""

import shutil
import subprocess

from . import UNIT_APPLY, UNIT_BOOT, UNIT_TIMER, UNIT_UPDATE
from .errors import RuGeoblockError

OWNED_UNITS = (UNIT_BOOT, UNIT_UPDATE, UNIT_APPLY, UNIT_TIMER)
ENABLE_UNITS = (UNIT_BOOT, UNIT_TIMER)
_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}


class Systemd:
    def __init__(self):
        self.binary = shutil.which("systemctl", path=_ENV["PATH"])

    @property
    def available(self) -> bool:
        return self.binary is not None

    def _run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        if not self.binary:
            raise RuGeoblockError("systemctl not found")
        try:
            return subprocess.run([self.binary, *args], capture_output=True, text=True,
                                  timeout=timeout, env=_ENV, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuGeoblockError(f"systemctl failed: {exc}") from None

    @staticmethod
    def _own(unit: str) -> str:
        if unit not in OWNED_UNITS:
            raise ValueError(f"{unit} is not a geoblock unit")
        return unit

    def state(self, verb: str, unit: str) -> str:
        """Return the stdout of is-enabled/is-active, or 'unavailable'."""
        if not self.available:
            return "unavailable"
        p = self._run(verb, self._own(unit))
        return p.stdout.strip() or "unknown"

    def enable_now(self, units=ENABLE_UNITS) -> None:
        p = self._run("enable", "--now", *map(self._own, units), timeout=120)
        if p.returncode != 0:
            raise RuGeoblockError("systemctl enable --now failed: " + p.stderr.strip()[:300])

    def disable_now(self, units=ENABLE_UNITS) -> None:
        p = self._run("disable", "--now", *map(self._own, units), timeout=120)
        if p.returncode != 0:
            raise RuGeoblockError("systemctl disable --now failed: " + p.stderr.strip()[:300])

    def daemon_reload(self) -> None:
        p = self._run("daemon-reload")
        if p.returncode != 0:
            raise RuGeoblockError("systemctl daemon-reload failed: " + p.stderr.strip()[:300])

    def show(self, unit: str, *props: str) -> dict:
        if not self.available:
            return {}
        p = self._run("show", self._own(unit), *[f"--property={x}" for x in props])
        out = {}
        for line in p.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out
