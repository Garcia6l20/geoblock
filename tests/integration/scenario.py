"""End-to-end scenario using the real nft inside a throwaway user+network namespace.

Run via tests/integration/test_netns.py (which wraps it in `unshare -Urn`). It never
touches the host network stack. A veth pair connects the namespace to a peer
namespace; the "blocked" test ranges contain the peer's address.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import helpers  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI = [sys.executable, "-I", os.path.join(ROOT, "bin", "geoblock")]
ENV = {**os.environ, "GEOBLOCK_TESTING": "1"}
tmp = helpers.tmpdir()
STATE = os.path.join(tmp, "state")
failures = []


def sh(*cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kw)


def cli(cfg, *args, expect=0):
    p = subprocess.run([*CLI, "--config", cfg, "--state-dir", STATE, "--no-systemd", *args],
                       capture_output=True, text=True, env=ENV)
    if p.returncode != expect:
        raise AssertionError(f"geoblock {' '.join(args)} exited {p.returncode}, expected {expect}\n"
                             f"stdout: {p.stdout}\nstderr: {p.stderr}")
    return p


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg, flush=True)
    if not cond:
        failures.append(msg)


# ---- network topology -----------------------------------------------------------
sh("ip", "link", "set", "lo", "up")
peer = subprocess.Popen(["unshare", "--net", "sleep", "600"])
time.sleep(0.5)
PID = str(peer.pid)


def ns(*cmd, check=True):
    return sh("nsenter", "-t", PID, "-n", *cmd, check=check)


sh("ip", "link", "add", "rgt0", "type", "veth", "peer", "name", "rgt1")
sh("ip", "link", "set", "rgt1", "netns", PID)
sh("ip", "addr", "add", "203.0.113.1/24", "dev", "rgt0")
sh("ip", "addr", "add", "2001:db8:1::1/64", "dev", "rgt0", "nodad")
sh("ip", "link", "set", "rgt0", "up")
ns("ip", "link", "set", "lo", "up")
ns("ip", "addr", "add", "203.0.113.2/24", "dev", "rgt1")
ns("ip", "addr", "add", "203.0.113.50/24", "dev", "rgt1")
ns("ip", "addr", "add", "2001:db8:1::2/64", "dev", "rgt1", "nodad")
ns("ip", "addr", "add", "2001:db8:1::50/64", "dev", "rgt1", "nodad")
ns("ip", "link", "set", "rgt1", "up")
time.sleep(1.0)

SERVER_CODE = (
    "import socket,sys\n"
    "fam=socket.AF_INET6 if sys.argv[1]=='6' else socket.AF_INET\n"
    "s=socket.socket(fam); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "if fam==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)\n"
    "s.bind(('::' if fam==socket.AF_INET6 else '0.0.0.0', 9000))\n"
    "s.listen(16)\nprint('ready',flush=True)\n"
    "while True:\n    c,_=s.accept(); c.close()\n"
)
CLIENT_CODE = (
    "import socket,sys\n"
    "fam=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET\n"
    "s=socket.socket(fam); s.settimeout(1.5)\n"
    "if len(sys.argv)>2: s.bind((sys.argv[2],0))\n"
    "try:\n    s.connect((sys.argv[1],9000)); print('ok')\n"
    "except ConnectionRefusedError: print('refused')\n"
    "except (TimeoutError,socket.timeout): print('timeout')\n"
    "except OSError as e: print('error',e.errno)\n"
)
servers = []
for fam in ("4", "6"):
    for prefix in ([], ["nsenter", "-t", PID, "-n"]):
        p = subprocess.Popen([*prefix, sys.executable, "-I", "-c", SERVER_CODE, fam],
                             stdout=subprocess.PIPE, text=True)
        p.stdout.readline()
        servers.append(p)


def connect(where, dst, src=None):
    prefix = ["nsenter", "-t", PID, "-n"] if where == "peer" else []
    args = [dst] + ([src] if src else [])
    return sh(*prefix, sys.executable, "-I", "-c", CLIENT_CODE, *args).stdout.strip()


def table_dump(*spec):
    # Packet/byte counters change with traffic; the rules themselves must not.
    return re.sub(r"packets \d+ bytes \d+", "packets N bytes N", sh("nft", "list", "table", *spec).stdout)


# ---- foreign firewall state that must never change --------------------------------
sh("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT")
sh("ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT")
sh("nft", "add", "table", "inet", "unrelated")
sh("nft", "add", "chain", "inet", "unrelated", "c", "{ type filter hook input priority 0; policy accept; }")
sh("nft", "add", "rule", "inet", "unrelated", "c", "tcp", "dport", "8080", "accept")
# iptables-restore materialises the missing built-in chains once; normalise before baselining.
sh("iptables-restore", input=sh("iptables-save").stdout)
sh("ip6tables-restore", input=sh("ip6tables-save").stdout)
foreign_before = (table_dump("ip", "filter"), table_dump("ip6", "filter"), table_dump("inet", "unrelated"))


def foreign_intact():
    return foreign_before == (table_dump("ip", "filter"), table_dump("ip6", "filter"),
                              table_dump("inet", "unrelated"))


def gb_table():
    p = sh("nft", "list", "table", "inet", "geoblock", check=False)
    return p.stdout if p.returncode == 0 else None


# ---- HTTPS provider and configuration ---------------------------------------------
server = helpers.Server(tmp)
cfg = helpers.write_config(tmp, server, output_action="reject")
PEER4, PEER6 = "203.0.113.2", "2001:db8:1::2"
OTHER4, OTHER6 = "203.0.113.50", "2001:db8:1::50"
server.routes["/xx-v4.zone"] = (200, helpers.zone(["203.0.113.2/32", "198.51.100.0/24"]))
server.routes["/xx-v6.zone"] = (200, helpers.zone(["2001:db8:1::2/128", "2001:db8:ffff::/48"]))

print("== baseline (no policy)")
check(connect("main", PEER4) == "ok" and connect("main", PEER6) == "ok", "baseline main->peer v4+v6")
check(connect("peer", "203.0.113.1") == "ok" and connect("peer", "2001:db8:1::1") == "ok", "baseline peer->main v4+v6")

print("== install (data only, must not activate)")
cli(cfg, "install", "--no-fetch")
cli(cfg, "update")
check(gb_table() is None, "update before enable does not load rules")
check(connect("main", PEER4) == "ok", "traffic still flows after update-without-enable")

print("== enable")
cli(cfg, "test")
cli(cfg, "enable", "--dry-run")
check(gb_table() is None, "enable --dry-run changes nothing")
cli(cfg, "enable")
check(gb_table() is not None, "table inet geoblock exists")
check(foreign_intact(), "unrelated tables untouched after enable")
check(connect("main", PEER4) == "refused", "outbound IPv4 to listed address is rejected")
check(connect("main", PEER6) == "refused", "outbound IPv6 to listed address is rejected")
check(connect("peer", "203.0.113.1", PEER4) == "timeout", "inbound IPv4 from listed source is dropped")
check(connect("peer", "2001:db8:1::1", PEER6) == "timeout", "inbound IPv6 from listed source is dropped")
check(connect("main", OTHER4) == "ok" and connect("main", OTHER6) == "ok", "outbound to unlisted addresses allowed (v4+v6)")
check(connect("peer", "203.0.113.1", OTHER4) == "ok" and connect("peer", "2001:db8:1::1", OTHER6) == "ok",
      "inbound from unlisted sources allowed (v4+v6)")
check(sh("python3", "-I", "-c", "import socket;s=socket.create_connection(('127.0.0.1',9000),2)", check=False).returncode != 3,
      "loopback is not blocked")
status = json.loads(cli(cfg, "status", "--json").stdout)
check(status["active"] is True and status["enabled"] is True and status["in_sync_with_current"] is True,
      "status reports enabled+active+in sync")
check(status["dataset"]["ipv4"] == 2 and status["dataset"]["ipv6"] == 2, "status shows entry counts")
check(status["runtime"]["counters"].get("geoblock-output-v4", 0) > 0, "counters record rejected packets")
listed = cli(cfg, "list", "--active", "--ipv4").stdout.split()
check("198.51.100.0/24" in listed and "203.0.113.2/32" in listed, "list --active shows kernel ranges")
check(cli(cfg, "list", "--match", PEER4).returncode == 0 and cli(cfg, "list", "--match", OTHER4, expect=1), "list --match")

print("== established connections are filtered immediately (no ct-state exemption)")
ECHO_CODE = (
    "import socket,threading\n"
    "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',9001)); s.listen(8)\n"
    "print('ready',flush=True)\n"
    "def h(c):\n    while True:\n        d=c.recv(10)\n        if not d: return\n        c.sendall(d)\n"
    "while True:\n    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()\n"
)
echo = subprocess.Popen(["nsenter", "-t", PID, "-n", sys.executable, "-I", "-c", ECHO_CODE], stdout=subprocess.PIPE, text=True)
echo.stdout.readline()
servers.append(echo)
CONN_CODE = (
    "import socket,sys\n"
    "s=socket.create_connection(('203.0.113.2',9001),3); s.settimeout(1.5); print('connected',flush=True)\n"
    "for _ in sys.stdin:\n"
    "    try:\n        s.sendall(b'x'); print('echo' if s.recv(1)==b'x' else 'closed',flush=True)\n"
    "    except OSError as e:\n        print('fail',flush=True)\n"
)
server.routes["/xx-v4.zone"] = (200, helpers.zone(["203.0.113.2/32"]))
server.routes["/xx-v6.zone"] = (200, helpers.zone(["2001:db8:1::2/128"]))
cli(cfg, "disable")
cli(cfg, "update")
conn = subprocess.Popen([sys.executable, "-I", "-c", CONN_CODE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
check(conn.stdout.readline().strip() == "connected", "long-lived connection established before enabling")
conn.stdin.write("\n")
conn.stdin.flush()
check(conn.stdout.readline().strip() == "echo", "established connection carries data before enable")
cli(cfg, "enable")
conn.stdin.write("\n")
conn.stdin.flush()
check(conn.stdout.readline().strip() == "fail", "established connection is cut immediately after enable")
cli(cfg, "disable")
conn.kill()
cli(cfg, "enable")


print("== UFW reload simulation (iptables-restore of the filter tables)")
saved4 = sh("iptables-save").stdout
saved6 = sh("ip6tables-save").stdout
sh("iptables", "-F")
sh("iptables-restore", input=saved4)
sh("ip6tables-restore", input=saved6)
check(gb_table() is not None and connect("main", PEER4) == "refused", "table survives iptables flush/restore")
check(foreign_intact(), "iptables-restore reproduces foreign rules and leaves them intact")

print("== failed update keeps the previous policy")
before = gb_table()
server.routes["/xx-v4.zone"] = (200, helpers.zone(["not-a-cidr"]))
cli(cfg, "update", expect=5)
server.routes["/xx-v4.zone"] = (200, helpers.zone(["203.0.113.2/32"]) + helpers.zone(["127.0.0.0/8"]))
cli(cfg, "update", expect=5)
server.routes["/xx-v4.zone"] = (500, "boom")
cli(cfg, "update", expect=5)
check(gb_table() == before, "rules identical after three failed updates")
check(connect("main", PEER4) == "refused", "policy still enforced after failed updates")

print("== update changes the dataset")
server.routes["/xx-v4.zone"] = (200, helpers.zone(["203.0.113.99/32", "198.51.100.0/24"]))
server.routes["/xx-v6.zone"] = (200, helpers.zone(["2001:db8:1::99/128", "2001:db8:ffff::/48"]))
cli(cfg, "update")
check(connect("main", PEER4) == "ok" and connect("main", PEER6) == "ok", "no longer blocked after dataset changes")
check(foreign_intact(), "unrelated tables untouched after update")

print("== rollback")
cli(cfg, "rollback", "--dry-run")
cli(cfg, "rollback")
check(connect("main", PEER4) == "refused" and connect("main", PEER6) == "refused", "rollback restores previous policy")

print("== reboot simulation")
sh("nft", "delete", "table", "inet", "geoblock")
check(connect("main", PEER4) == "ok", "after simulated reboot rules are gone")
cli(cfg, "load")
check(connect("main", PEER4) == "refused", "'load' restores the persisted generation")

print("== allowlist and input-only/forward configuration")
cfg2 = helpers.write_config(tmp, server, allow_ipv4="203.0.113.2/32", output_action="drop")
cli(cfg2, "enable")
check(connect("main", PEER4) == "ok", "allowlist exempts the listed IPv4 host")
check(connect("main", PEER6) == "timeout", "output_action=drop makes blocked IPv6 time out; allowlist is per family")
cli(cfg2, "check-config", "--show")
cli(cfg, "enable")

print("== tampered current generation is detected at load")
gen = os.path.join(STATE, "current")
with open(os.path.join(gen, "ruleset.nft"), "a") as fh:
    fh.write("# tampered\n")
sh("nft", "delete", "table", "inet", "geoblock")
cli(cfg, "load", expect=5)
check(gb_table() is None, "tampered ruleset was not loaded")
shutil.rmtree(STATE + "/generations", ignore_errors=True)
os.unlink(STATE + "/current")
os.unlink(STATE + "/previous")
cli(cfg, "update")  # recover: fresh generation
cli(cfg, "enable")

print("== disable / uninstall")
cli(cfg, "disable")
check(gb_table() is None, "disable removes the table")
check(connect("main", PEER4) == "ok", "traffic flows after disable")
check(foreign_intact(), "unrelated tables untouched after disable")
cli(cfg, "enable")
cli(cfg, "uninstall", "--purge")
check(gb_table() is None and not os.path.exists(STATE + "/current"), "uninstall --purge removes table and data")
check(foreign_intact(), "unrelated tables untouched after uninstall")

server.close()
for p in servers + [peer]:
    p.kill()
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
