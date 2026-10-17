"""Strict configuration parser. Only whitelisted keys, typed and range-checked."""

import ipaddress
import os
import re
import stat
from dataclasses import dataclass, fields
from urllib.parse import urlsplit

from .errors import ConfigError

MAX_CONFIG_BYTES = 64 * 1024
_LINE_RE = re.compile(r"^([a-z0-9_]+)\s*=\s*(.*)$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def _bool(v: str) -> bool:
    if v == "yes":
        return True
    if v == "no":
        return False
    raise ValueError("must be 'yes' or 'no'")


def _int(lo: int, hi: int):
    def parse(v: str) -> int:
        if not re.fullmatch(r"-?[0-9]{1,6}", v):
            raise ValueError("must be an integer")
        n = int(v)
        if not lo <= n <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return n

    return parse


def _enum(*choices: str):
    def parse(v: str) -> str:
        if v not in choices:
            raise ValueError("must be one of: " + ", ".join(choices))
        return v

    return parse


def _https_url(v: str) -> str:
    if not v:
        return ""
    if "{cc}" not in v:
        raise ValueError("must contain the {cc} placeholder (replaced by the country code)")
    parts = urlsplit(v.replace("{cc}", "xx"))
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("must be an https:// URL")
    if parts.username or parts.password:
        raise ValueError("credentials in URLs are not allowed")
    if any(c.isspace() or ord(c) < 32 for c in v) or len(v) > 512:
        raise ValueError("invalid URL")
    return v


def _cidr_list(version: int):
    def parse(v: str) -> tuple:
        out = []
        for item in (p.strip() for p in v.split(",")):
            if not item:
                continue
            if "/" not in item:
                raise ValueError(f"'{item}' is not a CIDR (missing prefix length)")
            try:
                net = ipaddress.ip_network(item, strict=True)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR '{item}': {exc}") from None
            if net.version != version:
                raise ValueError(f"'{item}' is not an IPv{version} CIDR")
            out.append(net)
        if len(out) > 256:
            raise ValueError("at most 256 entries allowed")
        return tuple(out)

    return parse


def _countries(v: str) -> tuple:
    out = []
    for item in (p.strip().lower() for p in v.split(",")):
        if not item:
            continue
        if not re.fullmatch(r"[a-z]{2}", item):
            raise ValueError(f"'{item}' is not a two-letter ISO 3166 country code")
        if item in out:
            raise ValueError(f"duplicate country '{item}'")
        out.append(item)
    if len(out) > 20:
        raise ValueError("at most 20 countries allowed")
    return tuple(out)


def _user(v: str) -> str:
    if v and not _USER_RE.match(v):
        raise ValueError("invalid user name")
    return v


def _path(v: str) -> str:
    if v and (not v.startswith("/") or "\0" in v or len(v) > 255):
        raise ValueError("must be an absolute path")
    return v


@dataclass(frozen=True)
class Settings:
    provider: str = "ipdeny"
    countries: tuple = ()
    ipv4_url: str = ""
    ipv6_url: str = ""
    ca_file: str = ""
    ipv4: bool = True
    ipv6: bool = True
    block_input: bool = True
    block_output: bool = True
    block_forward: bool = False
    output_action: str = "reject"
    hook_priority: int = -10
    allow_ipv4: tuple = ()
    allow_ipv6: tuple = ()
    connect_timeout: int = 15
    download_timeout: int = 120
    retries: int = 3
    retry_delay: int = 5
    max_download_bytes: int = 4 * 1024 * 1024
    min_entries_v4: int = 10
    min_entries_v6: int = 1
    max_shrink_percent: int = 50
    keep_generations: int = 5
    log_level: str = "info"
    service_user: str = "geoblock"


_PARSERS = {
    "provider": _enum("ipdeny"),
    "countries": _countries,
    "ipv4_url": _https_url,
    "ipv6_url": _https_url,
    "ca_file": _path,
    "ipv4": _bool,
    "ipv6": _bool,
    "block_input": _bool,
    "block_output": _bool,
    "block_forward": _bool,
    "output_action": _enum("reject", "drop"),
    "hook_priority": _int(-100, 100),
    "allow_ipv4": _cidr_list(4),
    "allow_ipv6": _cidr_list(6),
    "connect_timeout": _int(1, 120),
    "download_timeout": _int(5, 900),
    "retries": _int(0, 5),
    "retry_delay": _int(1, 300),
    "max_download_bytes": _int(1024, 64 * 1024 * 1024),
    "min_entries_v4": _int(1, 10_000_000),
    "min_entries_v6": _int(1, 10_000_000),
    "max_shrink_percent": _int(0, 100),
    "keep_generations": _int(2, 50),
    "log_level": _enum("error", "warning", "info", "debug"),
    "service_user": _user,
}

# Settings that change the generated ruleset (stored in generation metadata).
RULESET_KEYS = (
    "ipv4", "ipv6", "block_input", "block_output", "block_forward",
    "output_action", "hook_priority", "allow_ipv4", "allow_ipv6",
)

assert set(_PARSERS) == {f.name for f in fields(Settings)}


def parse_text(text: str, source: str = "<config>") -> Settings:
    values: dict = {}
    seen: set = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"\s+#.*$", "", raw).strip()
        if not line or line.startswith("#"):
            continue
        if any(ord(c) < 32 for c in line):
            raise ConfigError(f"{source}:{lineno}: control character in line")
        m = _LINE_RE.match(line)
        if not m:
            raise ConfigError(f"{source}:{lineno}: expected 'key = value'")
        key, val = m.group(1), m.group(2).strip()
        if key not in _PARSERS:
            raise ConfigError(f"{source}:{lineno}: unknown option '{key}'")
        if key in seen:
            raise ConfigError(f"{source}:{lineno}: duplicate option '{key}'")
        seen.add(key)
        try:
            values[key] = _PARSERS[key](val)
        except ValueError as exc:
            raise ConfigError(f"{source}:{lineno}: {key}: {exc}") from None
    settings = Settings(**values)
    if not (settings.ipv4 or settings.ipv6):
        raise ConfigError(f"{source}: ipv4 and ipv6 can not both be disabled")
    if not (settings.block_input or settings.block_output or settings.block_forward):
        raise ConfigError(f"{source}: at least one of block_input/block_output/block_forward is required")
    return settings


def load(path: str, require_root_owned: bool = False) -> Settings:
    """Load a config file. A missing file yields defaults."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return Settings()
    except OSError as exc:
        raise ConfigError(f"{path}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{path}: not a regular file")
        if st.st_mode & 0o022:
            raise ConfigError(f"{path}: must not be group- or world-writable")
        if require_root_owned and st.st_uid != 0:
            raise ConfigError(f"{path}: must be owned by root")
        if st.st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path}: file too large")
        data = fh.read(MAX_CONFIG_BYTES + 1)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not valid UTF-8") from None
    return parse_text(text, path)


def describe(settings: Settings) -> dict:
    out = {}
    for f in fields(Settings):
        v = getattr(settings, f.name)
        if isinstance(v, tuple):
            v = [str(x) for x in v]
        out[f.name] = v
    return out
