"""Environment and firewall-compatibility detection. Read-only; never changes anything."""

import os
import re
import subprocess
from dataclasses import dataclass, field

from .errors import PreflightError
from .nftables import Nft

_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
SUPPORTED_IDS = {"arch", "cachyos", "manjaro", "endeavouros", "garuda", "artix"}
MINIMAL_RULESET = (
    "add table inet geoblock\ndelete table inet geoblock\n"
    "table inet geoblock {\n\tchain input {\n"
    "\t\ttype filter hook input priority -10; policy accept;\n\t}\n}\n"
)


@dataclass
class Finding:
    level: str  # error | warning | info
    code: str
    message: str


@dataclass
class Report:
    findings: list = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def add(self, level: str, code: str, message: str) -> None:
        self.findings.append(Finding(level, code, message))

    @property
    def errors(self) -> list:
        return [f for f in self.findings if f.level == "error"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def require_ok(self) -> None:
        if self.errors:
            raise PreflightError("; ".join(f"{e.message}" for e in self.errors))


def _run(*cmd: str) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=_ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout.strip()


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(1024 * 1024)
    except OSError:
        return ""


def os_release(path: str = "/etc/os-release") -> dict:
    out = {}
    for line in _read(path).splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"')
    return out


def detect(nft: Nft, systemctl: bool = True, os_release_path: str = "/etc/os-release",
           sys_class_net: str = "/sys/class/net") -> Report:
    r = Report()

    rel = os_release(os_release_path)
    ids = {rel.get("ID", "")} | set(rel.get("ID_LIKE", "").split())
    r.facts["os"] = rel.get("PRETTY_NAME", "unknown")
    if ids & SUPPORTED_IDS:
        r.facts["os_supported"] = True
    else:
        r.facts["os_supported"] = False
        r.add("warning", "os-unsupported",
              f"{r.facts['os']} is not an Arch-based distribution; untested (nftables is generic)")

    # nftables availability and kernel support
    if not nft.available:
        r.add("error", "nft-missing", "nft not found; install the 'nftables' package")
    else:
        r.facts["nft_version"] = _run(nft.binary, "--version")
        try:
            nft.check(MINIMAL_RULESET)
        except Exception as exc:  # noqa: BLE001
            r.add("error", "nft-unusable",
                  f"nftables rejected a minimal ruleset (kernel support missing?): {exc}")

    def active(unit: str) -> bool:
        return systemctl and _run("systemctl", "is-active", unit) == "active"

    def enabled(unit: str) -> bool:
        return systemctl and _run("systemctl", "is-enabled", unit) in ("enabled", "static")

    # UFW and the iptables backend it uses
    ufw_bin = any(os.access(p, os.X_OK) for p in ("/usr/bin/ufw", "/usr/sbin/ufw"))
    r.facts["ufw_installed"] = ufw_bin
    r.facts["ufw_active"] = bool(ufw_bin and active("ufw.service"))
    ipt = _run("iptables", "--version")
    if "nf_tables" in ipt:
        r.facts["iptables_backend"] = "iptables-nft"
    elif "legacy" in ipt:
        r.facts["iptables_backend"] = "iptables-legacy"
    else:
        r.facts["iptables_backend"] = "none" if not ipt else "unknown"
    if ufw_bin and not r.facts["ufw_active"]:
        r.add("info", "ufw-inactive", "UFW is installed but not active; geoblock works independently of it")
    if r.facts["iptables_backend"] == "iptables-legacy" and r.facts["ufw_active"]:
        r.add("info", "iptables-legacy",
              "UFW uses iptables-legacy; legacy rules and the nft table are evaluated independently (untested)")

    # Other firewall managers
    if active("firewalld.service"):
        r.add("error", "firewalld-active",
              "firewalld is active; coexistence with geoblock is not verified and it is refused")
    for unit in ("shorewall.service", "shorewall6.service", "ferm.service", "fail2ban.service"):
        if active(unit):
            lvl = "info" if unit.startswith("fail2ban") else "warning"
            r.add(lvl, f"{unit.split('.')[0]}-active",
                  f"{unit} is active; geoblock does not interact with it (untested)")
    if enabled("nftables.service"):
        conf = _read("/etc/nftables.conf")
        if re.search(r"^\s*flush\s+ruleset", conf, re.M):
            r.add("warning", "nftables-flush",
                  "nftables.service is enabled and /etc/nftables.conf uses 'flush ruleset'; "
                  "restarting or reloading it removes the geoblock table until geoblock.service reruns")
    if active("docker.service") or active("podman.socket"):
        r.add("info", "containers",
              "container runtime active; container traffic traverses the forward hook "
              "(set block_forward = yes to filter it)")

    # VPN interfaces
    try:
        nics = os.listdir(sys_class_net)
    except OSError:
        nics = []
    vpns = sorted(n for n in nics if re.match(r"^(tun|tap|wg|tailscale|ppp|vpn)", n))
    if vpns:
        r.facts["vpn_interfaces"] = vpns
        r.add("info", "vpn-present",
              f"VPN-like interfaces found ({', '.join(vpns)}); outbound blocking applies to the "
              "post-NAT destination of packets leaving the host, including VPN endpoints in a blocked country")
    return r
