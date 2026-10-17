"""Persistent state: generations, the current/previous pointers, locks, metadata.

Layout under the state directory:
  generations/<id>/{ipv4.txt,ipv6.txt,ruleset.nft,meta.json}   immutable once published
  current -> generations/<id>      active known-good generation (loaded at boot)
  previous -> generations/<id>     the generation before `current`, for rollback
  state.json                       {"enabled": bool}
  last_update.json                 outcome of the last apply attempt
  staging/                         written by the unprivileged fetcher (untrusted)
"""

import fcntl
import json
import os
import re
import secrets
import shutil
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, UTC

from .errors import BusyError, DataError, NotReadyError, RuGeoblockError

GEN_RE = re.compile(r"^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}$")
GEN_FILES = ("ipv4.txt", "ipv6.txt", "ruleset.nft", "meta.json")
MAX_JSON_BYTES = 1024 * 1024


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    """Write via temp file + fsync + rename so readers never see partial content."""
    d = os.path.dirname(path)
    tmp = os.path.join(d, f".tmp-{secrets.token_hex(6)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(d)


def read_regular(path: str, max_bytes: int, dir_fd: int | None = None) -> bytes:
    """Read a regular file without following symlinks, bounded in size."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise DataError(f"can not open {os.path.basename(path)}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise DataError(f"{os.path.basename(path)} is not a regular file")
        if st.st_size > max_bytes:
            raise DataError(f"{os.path.basename(path)} is larger than {max_bytes} bytes")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise DataError(f"{os.path.basename(path)} is larger than {max_bytes} bytes")
    return data


def read_json(path: str, default=None):
    try:
        data = read_regular(path, MAX_JSON_BYTES)
    except FileNotFoundError:
        return default
    except DataError:
        return default
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return default
    return value


def dump_json(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


@dataclass
class Generation:
    id: str
    path: str
    meta: dict

    def read(self, name: str, max_bytes: int = 64 * 1024 * 1024) -> str:
        return read_regular(os.path.join(self.path, name), max_bytes).decode()


class State:
    def __init__(self, state_dir: str):
        self.dir = state_dir
        self.gen_dir = os.path.join(state_dir, "generations")
        self.staging = os.path.join(state_dir, "staging")
        self.current_link = os.path.join(state_dir, "current")
        self.previous_link = os.path.join(state_dir, "previous")
        self.state_file = os.path.join(state_dir, "state.json")
        self.last_update_file = os.path.join(state_dir, "last_update.json")
        self.lock_file = os.path.join(state_dir, ".state.lock")

    # -- locking ------------------------------------------------------------------
    @contextmanager
    def lock(self, path: str | None = None, wait: float = 0.0):
        """Exclusive advisory lock. Fails fast with BusyError unless `wait` > 0."""
        path = path or self.lock_file
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        except OSError as exc:
            raise RuGeoblockError(f"can not open lock file {path}: {exc.strerror}") from None
        try:
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise BusyError("another geoblock operation is in progress") from None
                    time.sleep(0.2)
            yield
        finally:
            os.close(fd)  # releases the flock

    @property
    def staging_lock(self) -> str:
        return os.path.join(self.staging, ".lock")

    # -- enabled flag -------------------------------------------------------------
    def is_enabled(self) -> bool:
        data = read_json(self.state_file, {})
        return bool(isinstance(data, dict) and data.get("enabled") is True)

    def set_enabled(self, value: bool) -> None:
        atomic_write(self.state_file, dump_json({"enabled": value, "changed": utcnow()}))

    # -- generations --------------------------------------------------------------
    def _link_target(self, link: str) -> str | None:
        try:
            target = os.readlink(link)
        except OSError:
            return None
        m = re.fullmatch(r"generations/([^/]+)", target)
        if not m or not GEN_RE.match(m.group(1)):
            return None
        return m.group(1)

    def load(self, gen_id: str) -> Generation:
        if not GEN_RE.match(gen_id):
            raise NotReadyError("invalid generation id")
        path = os.path.join(self.gen_dir, gen_id)
        meta = read_json(os.path.join(path, "meta.json"))
        if not isinstance(meta, dict):
            raise NotReadyError(f"generation {gen_id} is missing or corrupt")
        return Generation(gen_id, path, meta)

    def current(self) -> Generation | None:
        gid = self._link_target(self.current_link)
        return self.load(gid) if gid else None

    def previous(self) -> Generation | None:
        gid = self._link_target(self.previous_link)
        if not gid:
            return None
        try:
            return self.load(gid)
        except NotReadyError:
            return None

    def list_ids(self) -> list:
        try:
            names = os.listdir(self.gen_dir)
        except FileNotFoundError:
            return []
        return sorted(n for n in names if GEN_RE.match(n))

    def create_generation(self, files: dict, meta: dict) -> Generation:
        """Write a complete generation into a temp dir, then rename it into place."""
        os.makedirs(self.gen_dir, mode=0o755, exist_ok=True)
        gid = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
        tmp = os.path.join(self.gen_dir, f".tmp-{gid}")
        os.mkdir(tmp, 0o755)
        try:
            meta = dict(meta, id=gid)
            for name, text in {**files, "meta.json": None}.items():
                data = dump_json(meta) if name == "meta.json" else text.encode()
                atomic_write(os.path.join(tmp, name), data, 0o644)
            final = os.path.join(self.gen_dir, gid)
            os.rename(tmp, final)
            _fsync_dir(self.gen_dir)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        return Generation(gid, final, meta)

    def _set_link(self, link: str, gid: str) -> None:
        tmp = f"{link}.tmp-{secrets.token_hex(4)}"
        os.symlink(f"generations/{gid}", tmp)
        try:
            os.replace(tmp, link)
        except BaseException:
            os.unlink(tmp)
            raise
        _fsync_dir(self.dir)

    def publish(self, gen: Generation) -> None:
        """Make gen current; the old current becomes previous. Pointer swaps are atomic."""
        old = self._link_target(self.current_link)
        if old and old != gen.id:
            self._set_link(self.previous_link, old)
        self._set_link(self.current_link, gen.id)

    def swap_back(self) -> Generation:
        """Rollback pointers: previous becomes current and current becomes previous."""
        prev = self.previous()
        if prev is None:
            raise NotReadyError("no previous generation is available")
        cur = self._link_target(self.current_link)
        self._set_link(self.current_link, prev.id)
        if cur:
            self._set_link(self.previous_link, cur)
        return prev

    def prune(self, keep: int) -> list:
        protected = {self._link_target(self.current_link), self._link_target(self.previous_link)}
        ids = self.list_ids()
        removed = []
        for gid in ids[:-keep] if keep < len(ids) else []:
            if gid in protected:
                continue
            shutil.rmtree(os.path.join(self.gen_dir, gid), ignore_errors=True)
            removed.append(gid)
        try:
            for name in os.listdir(self.gen_dir):
                if name.startswith(".tmp-"):
                    shutil.rmtree(os.path.join(self.gen_dir, name), ignore_errors=True)
        except FileNotFoundError:
            pass
        return removed

    # -- last attempt -------------------------------------------------------------
    def record_attempt(self, ok: bool, message: str, **extra) -> None:
        prev = read_json(self.last_update_file, {}) or {}
        rec = {"time": utcnow(), "ok": ok, "message": message[:500], **extra}
        if ok:
            rec["last_success"] = rec["time"]
        elif isinstance(prev, dict) and prev.get("last_success"):
            rec["last_success"] = prev["last_success"]
        try:
            atomic_write(self.last_update_file, dump_json(rec))
        except OSError:
            pass
