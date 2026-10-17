"""Native nftables backend: renders, checks, loads and inspects the geoblock table.

Only the table `inet geoblock` is ever touched. Every ruleset starts with
`add table` + `delete table` for that table so loading is an atomic replace
(one netlink transaction) that also works when the table does not exist yet.
Callers can not pass arbitrary nft commands; the public methods build fixed ones.
"""

import ipaddress
import json
import os
import shutil
import subprocess
from dataclasses import dataclass

from . import NFT_FAMILY, NFT_TABLE, cidr
from .config import Settings
from .errors import FirewallError

NFT_CANDIDATES = ("/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft", "/bin/nft")
UNSHARE_CANDIDATES = ("/usr/bin/unshare", "/bin/unshare")
CLEAN_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
NFT_TIMEOUT = 60
ELEMENTS_PER_LINE = 6

COMMENT_TABLE = "managed by geoblock; do not edit"


def _find(candidates):
    for c in candidates:
        if os.access(c, os.X_OK):
            return c
    return None


def render_ruleset(settings: Settings, v4: tuple, v6: tuple) -> str:
    """Generate the complete replacement ruleset text from validated networks."""
    want4 = settings.ipv4 and bool(v4)
    want6 = settings.ipv6 and bool(v6)
    out = [
        f"add table {NFT_FAMILY} {NFT_TABLE}",
        f"delete table {NFT_FAMILY} {NFT_TABLE}",
        f"table {NFT_FAMILY} {NFT_TABLE} {{",
        f'\tcomment "{COMMENT_TABLE}"',
    ]

    def add_set(name: str, typ: str, nets) -> None:
        out.append(f"\tset {name} {{")
        out.append(f"\t\ttype {typ}")
        out.append("\t\tflags interval")
        items = [str(n) for n in nets]
        if items:
            out.append("\t\telements = {")
            for i in range(0, len(items), ELEMENTS_PER_LINE):
                chunk = ", ".join(items[i:i + ELEMENTS_PER_LINE])
                last = i + ELEMENTS_PER_LINE >= len(items)
                out.append(f"\t\t\t{chunk}{'' if last else ','}")
            out.append("\t\t}")
        out.append("\t}")

    allow4 = settings.allow_ipv4 if want4 else ()
    allow6 = settings.allow_ipv6 if want6 else ()
    if want4:
        add_set("blocked_v4", "ipv4_addr", v4)
    if want6:
        add_set("blocked_v6", "ipv6_addr", v6)
    if allow4:
        add_set("allow_v4", "ipv4_addr", allow4)
    if allow6:
        add_set("allow_v6", "ipv6_addr", allow6)

    def add_chain(name: str, enabled: bool, direction: str, verdict: str) -> None:
        if not enabled:
            return
        match = "saddr" if direction == "in" else "daddr"
        loop = "iifname" if direction == "in" else "oifname"
        out.append(f"\tchain {name} {{")
        out.append(f"\t\ttype filter hook {name} priority {settings.hook_priority}; policy accept;")
        out.append(f'\t\t{loop} "lo" accept comment "geoblock-{name}-loopback"')
        if allow4:
            out.append(f'\t\tip {match} @allow_v4 accept comment "geoblock-{name}-allow-v4"')
        if allow6:
            out.append(f'\t\tip6 {match} @allow_v6 accept comment "geoblock-{name}-allow-v6"')
        if want4:
            out.append(f'\t\tip {match} @blocked_v4 counter {verdict} comment "geoblock-{name}-v4"')
        if want6:
            out.append(f'\t\tip6 {match} @blocked_v6 counter {verdict} comment "geoblock-{name}-v6"')
        out.append("\t}")

    add_chain("input", settings.block_input, "in", "drop")
    add_chain("output", settings.block_output, "out", settings.output_action)
    # Forwarded traffic has both a source and a destination; either side matching drops it.
    if settings.block_forward:
        out.append("\tchain forward {")
        out.append(f"\t\ttype filter hook forward priority {settings.hook_priority}; policy accept;")
        for fam, flag, setname in (("ip", want4, "blocked_v4"), ("ip6", want6, "blocked_v6")):
            if flag:
                tag = "v4" if fam == "ip" else "v6"
                out.append(f'\t\t{fam} saddr @{setname} counter drop comment "geoblock-forward-src-{tag}"')
                out.append(f'\t\t{fam} daddr @{setname} counter drop comment "geoblock-forward-dst-{tag}"')
        out.append("\t}")
    out.append("}")
    return "\n".join(out) + "\n"


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


def _is_permission_error(stderr: str) -> bool:
    s = stderr.lower()
    return "operation not permitted" in s or "must be root" in s or "permission denied" in s


class Nft:
    def __init__(self, binary: str | None = None, unshare: str | None = None):
        self.binary = binary or _find(NFT_CANDIDATES)
        self.unshare = unshare or _find(UNSHARE_CANDIDATES) or shutil.which("unshare")

    @property
    def available(self) -> bool:
        return self.binary is not None

    def _run(self, args, stdin: str | None = None, wrap_userns: bool = False) -> RunResult:
        if not self.binary:
            raise FirewallError("nft binary not found (install the 'nftables' package)")
        cmd = [self.binary, *args]
        if wrap_userns:
            cmd = [self.unshare, "--user", "--map-root-user", "--net", *cmd]
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                               timeout=NFT_TIMEOUT, env=CLEAN_ENV, check=False)
        except subprocess.TimeoutExpired:
            raise FirewallError("nft timed out") from None
        except OSError as exc:
            raise FirewallError(f"can not run nft: {exc}") from None
        return RunResult(p.returncode, p.stdout, p.stderr)

    def check(self, ruleset: str) -> None:
        """Validate a ruleset without touching the host. Raises FirewallError if rejected.

        Falls back to an unprivileged user+network namespace when the caller lacks
        CAP_NET_ADMIN, so `test` and `--dry-run` work for ordinary users.
        """
        res = self._run(["-c", "-f", "-"], stdin=ruleset)
        if res.returncode != 0 and _is_permission_error(res.stderr) and self.unshare:
            res = self._run(["-c", "-f", "-"], stdin=ruleset, wrap_userns=True)
        if res.returncode != 0:
            raise FirewallError("nft rejected the ruleset: " + _first_line(res.stderr))

    def load(self, ruleset: str) -> None:
        """Atomically replace the project table. Other tables are not referenced."""
        res = self._run(["-f", "-"], stdin=ruleset)
        if res.returncode != 0:
            raise FirewallError("nft failed to load the ruleset: " + _first_line(res.stderr))

    def delete_table(self) -> None:
        script = f"add table {NFT_FAMILY} {NFT_TABLE}\ndelete table {NFT_FAMILY} {NFT_TABLE}\n"
        res = self._run(["-f", "-"], stdin=script)
        if res.returncode != 0:
            raise FirewallError("nft failed to delete the table: " + _first_line(res.stderr))

    def list_table(self):
        """Return the parsed JSON listing of the project table, or None if absent.

        Raises FirewallError when the state can not be determined (e.g. not root).
        """
        res = self._run(["-j", "list", "table", NFT_FAMILY, NFT_TABLE])
        if res.returncode != 0:
            if _is_permission_error(res.stderr):
                raise FirewallError("insufficient privileges to read the nftables state")
            if "no such file or directory" in res.stderr.lower():
                return None
            raise FirewallError("nft list failed: " + _first_line(res.stderr))
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            raise FirewallError("nft returned unparsable JSON") from None


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return "no error output"


# --- inspection of the installed table -------------------------------------------------

def _elem_ranges(elem) -> list:
    """Convert one nft JSON set element to integer ranges."""
    if isinstance(elem, str):
        a = int(ipaddress.ip_address(elem))
        return [(a, a)]
    if isinstance(elem, dict):
        if "prefix" in elem:
            net = ipaddress.ip_network(f"{elem['prefix']['addr']}/{elem['prefix']['len']}")
            return [(int(net.network_address), int(net.broadcast_address))]
        if "range" in elem:
            lo, hi = elem["range"]
            return [(int(ipaddress.ip_address(lo)), int(ipaddress.ip_address(hi)))]
        if "elem" in elem:
            return _elem_ranges(elem["elem"]["val"])
    raise FirewallError("unrecognised element in nft set listing")


def parse_listing(listing) -> dict:
    """Reduce an `nft -j list table` result to {sets, chains, rules}."""
    sets: dict = {}
    chains: dict = {}
    rules: dict = {}
    for item in listing.get("nftables", []):
        if "set" in item:
            s = item["set"]
            ranges = []
            for e in s.get("elem", []):
                ranges.extend(_elem_ranges(e))
            sets[s["name"]] = cidr.to_ranges_from_ints(ranges)
        elif "chain" in item:
            c = item["chain"]
            chains[c["name"]] = {"hook": c.get("hook"), "prio": c.get("prio"),
                                 "policy": c.get("policy"), "type": c.get("type")}
        elif "rule" in item:
            r = item["rule"]
            pkts = 0
            for expr in r.get("expr", []):
                if "counter" in expr:
                    pkts = expr["counter"].get("packets", 0)
            rules[r.get("comment", f"handle-{r.get('handle')}")] = {
                "chain": r["chain"], "packets": pkts}
    return {"sets": sets, "chains": chains, "rules": rules}


def expected_ranges(networks) -> list:
    return cidr.to_ranges(networks)


def verify_listing(listing, settings: Settings, v4: tuple, v6: tuple) -> None:
    """Raise FirewallError unless the installed table matches what was generated."""
    if listing is None:
        raise FirewallError("table is not installed after loading")
    got = parse_listing(listing)
    want = {}
    if settings.ipv4 and v4:
        want["blocked_v4"] = expected_ranges(v4)
    if settings.ipv6 and v6:
        want["blocked_v6"] = expected_ranges(v6)
    for name, ranges in want.items():
        if got["sets"].get(name) != ranges:
            raise FirewallError(f"installed set {name} does not match the generated data")
    for name in ("input", "output", "forward"):
        enabled = getattr(settings, f"block_{name}")
        have = got["chains"].get(name)
        if enabled and (have is None or have["hook"] != name or have["prio"] != settings.hook_priority):
            raise FirewallError(f"chain {name} is missing or misconfigured")
        if not enabled and have is not None:
            raise FirewallError(f"chain {name} is installed but disabled in the configuration")
