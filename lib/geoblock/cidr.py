"""Strict parsing and validation of CIDR zone files (one prefix per line)."""

import ipaddress
import re
from dataclasses import dataclass

from .errors import DataError

MAX_LINES = 200_000
_V4_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$")
_V6_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}/[0-9]{1,3}$")
_RE = {4: _V4_RE, 6: _V6_RE}

# Prefixes that must never be blocked by a country list: they would cut off the
# host from itself, its LAN, or the whole internet. Any overlap rejects the dataset.
_PROTECTED = {
    4: [ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")],
    6: [ipaddress.ip_network(n) for n in (
        "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8")],
}
_MIN_PREFIXLEN = {4: 8, 6: 16}


@dataclass(frozen=True)
class Dataset:
    family: int
    networks: tuple  # unique, sorted, as parsed
    collapsed: tuple  # minimal covering set
    raw_lines: int
    duplicates: int

    @property
    def count(self) -> int:
        return len(self.networks)


def _short(line: str) -> str:
    return line[:40] + ("..." if len(line) > 40 else "")


def parse_zone(text: str, family: int) -> Dataset:
    """Parse and strictly validate a zone file. Raises DataError on any bad line."""
    if family not in (4, 6):
        raise ValueError("family must be 4 or 6")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise DataError(f"IPv{family} dataset has too many lines (>{MAX_LINES})")
    seen = set()
    duplicates = 0
    nets = []
    for lineno, line in enumerate(lines, 1):
        if line == "" or line.startswith("#"):
            continue
        if not _RE[family].match(line):
            raise DataError(f"IPv{family} dataset line {lineno}: not a valid IPv{family} CIDR: {_short(line)!r}")
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError as exc:
            raise DataError(f"IPv{family} dataset line {lineno}: {exc}") from None
        if net.version != family:
            raise DataError(f"IPv{family} dataset line {lineno}: wrong address family")
        if net.prefixlen < _MIN_PREFIXLEN[family]:
            raise DataError(f"IPv{family} dataset line {lineno}: implausibly large prefix /{net.prefixlen}")
        if net in seen:
            duplicates += 1
            continue
        seen.add(net)
        nets.append(net)
    nets.sort()
    for prot in _PROTECTED[family]:
        for net in nets:
            if net.overlaps(prot):
                raise DataError(
                    f"IPv{family} dataset contains {net}, which overlaps the protected range {prot}"
                )
    collapsed = tuple(ipaddress.collapse_addresses(nets))
    return Dataset(family, tuple(nets), collapsed, len(lines), duplicates)


def validate_dataset(text: str, family: int, min_entries: int) -> Dataset:
    ds = parse_zone(text, family)
    if ds.count < min_entries:
        raise DataError(
            f"IPv{family} dataset has {ds.count} entries, below the configured minimum of {min_entries}"
        )
    return ds


def merge(datasets, family: int) -> "Dataset":
    """Union of per-country datasets of one family."""
    nets = sorted({n for ds in datasets for n in ds.networks})
    return Dataset(family, tuple(nets), tuple(ipaddress.collapse_addresses(nets)),
                   sum(d.raw_lines for d in datasets), sum(d.duplicates for d in datasets))


def check_shrink(new_count: int, old_count: int, max_percent: int, family: int) -> None:
    """Reject updates that remove an implausible share of the previous dataset."""
    if old_count <= 0 or max_percent >= 100:
        return
    floor = old_count * (100 - max_percent) // 100
    if new_count < floor:
        raise DataError(
            f"IPv{family} dataset shrank from {old_count} to {new_count} entries "
            f"(more than max_shrink_percent={max_percent}%)"
        )


def render_lines(networks) -> str:
    return "".join(f"{n}\n" for n in networks)


def to_ranges(networks) -> list:
    """Merge networks into sorted, non-adjacent integer (start, end) ranges."""
    return to_ranges_from_ints((int(n.network_address), int(n.broadcast_address)) for n in networks)


def to_ranges_from_ints(pairs) -> list:
    ranges = sorted(pairs)
    merged: list = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def contains(networks, address: str):
    """Return the first network containing address, or None."""
    addr = ipaddress.ip_address(address)
    for net in networks:
        if net.version == addr.version and addr in net:
            return net
    return None
