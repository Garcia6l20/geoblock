"""Command-line interface."""

import argparse
import json
import os
import pwd
import shutil
import subprocess
import sys

from . import (DEFAULT_CONFIG, DEFAULT_STATE_DIR, NFT_FAMILY, NFT_TABLE, PROG, UNIT_BOOT,
               UNIT_TIMER, UNIT_UPDATE, __version__, cidr, log)
from . import config as config_mod
from . import engine, preflight
from .errors import (EXIT_OK, ConfigError, DataError, NotReadyError,
                     PreflightError, PrivilegeError, RuGeoblockError)
from .nftables import Nft
from .state import State, read_json
from .systemd import Systemd

EXAMPLE_CONFIGS = ("/usr/local/share/doc/geoblock/geoblock.conf.example",
                   "/usr/share/doc/geoblock/geoblock.conf.example")
_CLEAN_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": "/nonexistent"}


class Context:
    def __init__(self, args):
        self.config_path = args.config
        self.state_dir = args.state_dir
        self.dry_run = getattr(args, "dry_run", False)
        self.use_systemd = not args.no_systemd
        self.settings = config_mod.load(self.config_path, require_root_owned=os.geteuid() == 0
                                        and os.environ.get("GEOBLOCK_TESTING") != "1")
        log.configure("debug" if args.verbose else self.settings.log_level)
        self.state = State(self.state_dir)
        self.nft = Nft()
        self.systemd = Systemd()
        self.engine = engine.Engine(self.settings, self.state, self.nft)

    def require_root(self) -> None:
        if os.geteuid() != 0:
            raise PrivilegeError(f"{PROG}: this command must be run as root (try: sudo {PROG} ...)")


def out(msg: str = "") -> None:
    print(msg)


# ---------------------------------------------------------------- helpers

def run_fetch(ctx: Context) -> dict:
    """Run the fetch stage, dropping root privileges when a service user is configured."""
    s = ctx.settings
    if os.geteuid() != 0 or not s.service_user:
        if os.geteuid() == 0:
            log.warning("service_user is empty: downloading as root (not recommended)")
        return engine.fetch_stage(s, ctx.state)
    try:
        pw = pwd.getpwnam(s.service_user)
    except KeyError:
        raise PreflightError(
            f"service user '{s.service_user}' does not exist; run 'systemd-sysusers' "
            "or install the package") from None
    cmd = [sys.executable, "-I", os.path.abspath(sys.argv[0]), "--config", ctx.config_path,
           "--state-dir", ctx.state_dir, "fetch"]
    p = subprocess.run(cmd, user=pw.pw_uid, group=pw.pw_gid, extra_groups=[], env=_CLEAN_ENV,
                       cwd="/", check=False, timeout=s.download_timeout * (s.retries + 2) + 60)
    if p.returncode != 0:
        raise DataError("the unprivileged fetch stage failed (see messages above)")
    return {}


def do_update(ctx: Context, activate: bool = False) -> engine.ApplyResult:
    run_fetch(ctx)
    return ctx.engine.apply_stage(activate=activate)


def describe_result(res: engine.ApplyResult) -> str:
    counts = ", ".join(f"{k}={v}" for k, v in sorted(res.counts.items()))
    return f"{res.message} (generation {res.generation or '-'}; {counts})"


def print_report(report: preflight.Report) -> None:
    for f in report.findings:
        out(f"  [{f.level.upper():7}] {f.message}")


# ---------------------------------------------------------------- commands

def cmd_check_config(ctx: Context, args) -> int:
    if args.show:
        out(json.dumps(config_mod.describe(ctx.settings), indent=2))
    out(f"configuration OK ({ctx.config_path})")
    return EXIT_OK


def cmd_install(ctx: Context, args) -> int:
    if not ctx.dry_run:
        ctx.require_root()
    report = preflight.detect(ctx.nft, systemctl=ctx.use_systemd)
    out("Environment check:")
    print_report(report)
    report.require_ok()
    steps = [f"create {ctx.state_dir} and {ctx.state.staging}",
             f"create {ctx.config_path} from the example if it is missing"]
    if ctx.use_systemd:
        steps.append("systemctl daemon-reload")
    if not args.no_fetch:
        steps.append("download and validate the country data and publish it (firewall NOT activated)")
    if ctx.dry_run:
        out("dry run; would:")
        for s in steps:
            out(f"  - {s}")
        return EXIT_OK
    os.makedirs(ctx.state_dir, mode=0o755, exist_ok=True)
    os.makedirs(ctx.state.staging, mode=0o755, exist_ok=True)
    s = ctx.settings
    if s.service_user:
        try:
            pw = pwd.getpwnam(s.service_user)
            os.chown(ctx.state.staging, pw.pw_uid, pw.pw_gid)
        except KeyError:
            log.warning(f"service user '{s.service_user}' does not exist; staging stays root-owned")
    example = next((p for p in EXAMPLE_CONFIGS if os.path.exists(p)), None)
    if not os.path.exists(ctx.config_path) and example:
        os.makedirs(os.path.dirname(ctx.config_path), mode=0o755, exist_ok=True)
        shutil.copyfile(example, ctx.config_path)
        os.chmod(ctx.config_path, 0o644)
        out(f"created {ctx.config_path}")
    if ctx.use_systemd:
        ctx.systemd.daemon_reload()
    if not args.no_fetch:
        res = do_update(ctx)
        out("dataset: " + describe_result(res))
    out("Installed. The firewall policy is NOT active yet; run: sudo geoblock enable")
    return EXIT_OK


def cmd_update(ctx: Context, args) -> int:
    if ctx.dry_run:
        _, per_country, _ = engine.download_datasets(ctx.settings)
        for (cc, fam), ds in sorted(per_country.items()):
            out(f"{cc.upper()} IPv{fam}: {ds.count} prefixes ({len(ds.collapsed)} merged, {ds.duplicates} duplicate lines)")
        from .nftables import render_ruleset
        datasets = engine.merge_countries(ctx.settings, per_country)
        ruleset = render_ruleset(ctx.settings,
                                 datasets[4].collapsed if 4 in datasets else (),
                                 datasets[6].collapsed if 6 in datasets else ())
        ctx.nft.check(ruleset)
        out("dry run: downloaded data is valid and the ruleset passes nft -c; nothing was changed")
        return EXIT_OK
    ctx.require_root()
    res = do_update(ctx)
    out("update: " + describe_result(res))
    if not res.activated:
        out("note: the firewall policy is not enabled; run 'geoblock enable' to activate it")
    return EXIT_OK


def cmd_enable(ctx: Context, args) -> int:
    if not ctx.dry_run:
        ctx.require_root()
    report = preflight.detect(ctx.nft, systemctl=ctx.use_systemd)
    out("Compatibility check:")
    print_report(report)
    report.require_ok()
    have_data = ctx.state.current() is not None
    if ctx.dry_run:
        if have_data:
            res = ctx.engine.apply_stage(dry_run=True, use_staged=False)
            out(res.message)
        else:
            out("dry run: no dataset yet; would download one, then load the rules")
        out("dry run: would load the rules now"
            + (", enable geoblock.service and the update timer" if ctx.use_systemd else ""))
        return EXIT_OK
    ctx.require_root()
    if not have_data:
        out("no dataset installed; downloading one first")
        run_fetch(ctx)
    res = ctx.engine.apply_stage(activate=True, use_staged=not have_data)
    out("rules loaded: " + describe_result(res))
    if ctx.use_systemd:
        ctx.systemd.enable_now()
        out(f"enabled {UNIT_BOOT} (load at boot) and {UNIT_TIMER} (daily updates)")
    else:
        out("systemd integration skipped (--no-systemd): rules are NOT persistent across reboot")
    return EXIT_OK


def cmd_disable(ctx: Context, args) -> int:
    if ctx.dry_run:
        out(ctx.engine.disable(dry_run=True))
        return EXIT_OK
    ctx.require_root()
    out(ctx.engine.disable())
    if ctx.use_systemd:
        ctx.systemd.disable_now()
        out(f"disabled {UNIT_BOOT} and {UNIT_TIMER}")
    return EXIT_OK


def cmd_rollback(ctx: Context, args) -> int:
    if not ctx.dry_run:
        ctx.require_root()
    out(ctx.engine.rollback(dry_run=ctx.dry_run))
    return EXIT_OK


def cmd_uninstall(ctx: Context, args) -> int:
    if ctx.dry_run:
        out("dry run; would delete the geoblock table, disable geoblock units"
            + (f", and delete {ctx.state_dir}" if args.purge else ", and keep stored data"))
        return EXIT_OK
    ctx.require_root()
    out(ctx.engine.disable())
    if ctx.use_systemd:
        ctx.systemd.disable_now()
    if args.purge:
        with ctx.state.lock(wait=30):
            for name in ("current", "previous", "state.json", "last_update.json"):
                p = os.path.join(ctx.state_dir, name)
                if os.path.lexists(p):
                    os.unlink(p)
            shutil.rmtree(ctx.state.gen_dir, ignore_errors=True)
            shutil.rmtree(ctx.state.staging, ignore_errors=True)
        out(f"removed stored data in {ctx.state_dir}")
    out("Firewall resources removed. Package files and /etc/geoblock are kept; "
        "remove them with your package manager or scripts/uninstall.sh.")
    return EXIT_OK


def cmd_list(ctx: Context, args) -> int:
    fams = [4] if args.ipv4 and not args.ipv6 else [6] if args.ipv6 and not args.ipv4 else [4, 6]
    if args.active:
        listing = ctx.nft.list_table()
        if listing is None:
            raise NotReadyError("the geoblock table is not loaded")
        sets = __import__("ipaddress")
        parsed = engine.parse_listing(listing)
        for fam in fams:
            ranges = parsed["sets"].get(f"blocked_v{fam}", [])
            if args.count:
                out(f"ipv{fam}: {len(ranges)} ranges")
                continue
            for lo, hi in ranges:
                a, b = (sets.ip_address(lo) if fam == 4 else sets.IPv6Address(lo),
                        sets.ip_address(hi) if fam == 4 else sets.IPv6Address(hi))
                out(", ".join(map(str, sets.summarize_address_range(a, b))))
        return EXIT_OK
    cur = ctx.state.current()
    if cur is None:
        raise NotReadyError("no dataset installed; run 'geoblock update'")
    for fam in fams:
        try:
            text = cur.read(f"ipv{fam}.txt")
        except FileNotFoundError:
            continue
        nets = cidr.parse_zone(text, fam).networks
        if args.match:
            hit = cidr.contains(nets, args.match) if _is_family(args.match, fam) else None
            if hit:
                out(f"{args.match} is covered by {hit}")
                return EXIT_OK
            continue
        if args.count:
            out(f"ipv{fam}: {len(nets)} prefixes")
        else:
            sys.stdout.write(cidr.render_lines(nets))
    if args.match:
        out(f"{args.match} is not covered by the installed dataset")
        return 1
    return EXIT_OK


def _is_family(addr: str, fam: int) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(addr).version == fam
    except ValueError:
        raise ConfigError(f"'{addr}' is not a valid IP address") from None


def cmd_test(ctx: Context, args) -> int:
    failures = 0

    def result(ok: bool, text: str, warn: bool = False) -> None:
        nonlocal failures
        out(f"  [{'PASS' if ok else 'WARN' if warn else 'FAIL'}] {text}")
        if not ok and not warn:
            failures += 1

    out("Tests (read-only; the active policy is not modified):")
    result(True, f"configuration {ctx.config_path} is valid")
    result(bool(ctx.settings.countries),
           "countries: " + (", ".join(c.upper() for c in ctx.settings.countries) or "none configured (set 'countries = xx')"))
    report = preflight.detect(ctx.nft, systemctl=ctx.use_systemd)
    for f in report.findings:
        if f.level == "error":
            result(False, f.message)
        elif f.level == "warning":
            result(False, f.message, warn=True)
    if report.ok:
        result(True, f"firewall compatibility ({report.facts.get('os')}, {report.facts.get('nft_version', 'nft ?')},"
                     f" iptables backend: {report.facts.get('iptables_backend')})")
    cur = ctx.state.current()
    if cur is None:
        result(False, "no dataset installed (run: sudo geoblock update)")
    else:
        try:
            datasets = engine._datasets_from_generation(ctx.settings, cur)
            for fam, ds in sorted(datasets.items()):
                result(ds.count >= engine.min_entries(ctx.settings, fam),
                       f"IPv{fam} dataset: {ds.count} prefixes, integrity OK")
            ruleset = ctx.engine._render(datasets)
            ctx.nft.check(ruleset)
            result(True, "generated ruleset passes 'nft -c' validation")
        except RuGeoblockError as exc:
            result(False, str(exc))
    if args.online:
        try:
            _, datasets, _ = engine.download_datasets(ctx.settings)
            result(True, "provider reachable; downloaded data validates: "
                   + ", ".join(f"{c.upper()}-IPv{f}={d.count}" for (c, f), d in sorted(datasets.items())))
        except RuGeoblockError as exc:
            result(False, f"online check: {exc}")
    out("RESULT: " + ("all checks passed" if not failures else f"{failures} check(s) failed"))
    return EXIT_OK if not failures else PreflightError.exit_code


def gather_status(ctx: Context) -> dict:
    st = {"version": __version__}
    cur = ctx.state.current()
    enabled = ctx.state.is_enabled()
    st["installed"] = os.path.isdir(ctx.state_dir) or os.path.exists(ctx.config_path)
    st["enabled"] = enabled
    st["backend"] = f"nftables, native table '{NFT_FAMILY} {NFT_TABLE}' (hook priority {ctx.settings.hook_priority})"
    rt = ctx.engine.runtime_info()
    st["runtime"] = rt
    if rt["state"] == "present" and cur is not None:
        st["in_sync_with_current"] = ctx.engine.runtime_in_sync(cur)
    st["active"] = {"present": True, "absent": False}.get(rt["state"], None)
    if cur:
        st["dataset"] = {"countries": cur.meta.get("countries"), "generation": cur.id, "created": cur.meta.get("created"),
                         "fetched_at": cur.meta.get("fetched_at"), "provider": cur.meta.get("provider"),
                         "ipv4": cur.meta.get("ipv4", {}).get("count"),
                         "ipv6": cur.meta.get("ipv6", {}).get("count")}
    st["previous_generation"] = (ctx.state.previous().id if ctx.state.previous() else None)
    st["last_attempt"] = read_json(ctx.state.last_update_file)
    st["last_fetch"] = engine.load_fetch_status(ctx.state)
    st["allowlist"] = [str(n) for n in ctx.settings.allow_ipv4 + ctx.settings.allow_ipv6]
    if ctx.use_systemd and ctx.systemd.available:
        sd = ctx.systemd
        timer = sd.show(UNIT_TIMER, "NextElapseUSecRealtime", "LastTriggerUSec")
        svc = sd.show(UNIT_UPDATE, "Result", "ExecMainStatus")
        st["systemd"] = {
            "boot_service": {"enabled": sd.state("is-enabled", UNIT_BOOT), "active": sd.state("is-active", UNIT_BOOT)},
            "timer": {"enabled": sd.state("is-enabled", UNIT_TIMER), "active": sd.state("is-active", UNIT_TIMER),
                      "next": timer.get("NextElapseUSecRealtime"), "last": timer.get("LastTriggerUSec")},
            "update_service": {"result": svc.get("Result"), "exit_status": svc.get("ExecMainStatus")},
        }
    return st


def cmd_status(ctx: Context, args) -> int:
    st = gather_status(ctx)
    if args.json:
        out(json.dumps(st, indent=2, sort_keys=True))
        return EXIT_OK
    rt = st["runtime"]
    active = {True: "yes", False: "no", None: "unknown (" + rt.get("detail", "need root") + ")"}[st["active"]]
    out(f"geoblock {st['version']}")
    out(f"  installed : {'yes' if st['installed'] else 'no'}")
    out(f"  enabled   : {'yes' if st['enabled'] else 'no'}   (policy requested, persists across reboot)")
    out(f"  active    : {active}   (rules currently loaded in the kernel)")
    if "in_sync_with_current" in st:
        out(f"  in sync   : {'yes' if st['in_sync_with_current'] else 'NO - loaded rules differ from the current dataset'}")
    out(f"  backend   : {st['backend']}")
    ds = st.get("dataset")
    if ds:
        out(f"  countries : {', '.join(c.upper() for c in ds.get('countries') or [])}")
        out(f"  dataset   : {ds['generation']} from {ds['provider']}, fetched {ds['fetched_at']}")
        out(f"  entries   : IPv4 {ds['ipv4']}, IPv6 {ds['ipv6']}")
    else:
        out("  dataset   : none installed")
    la = st.get("last_attempt") or {}
    if la:
        out(f"  last update : {la.get('last_success', 'never')} (last attempt {la.get('time')}: "
            f"{'ok' if la.get('ok') else 'FAILED'} - {la.get('message')})")
    lf = st.get("last_fetch") or {}
    if lf and not lf.get("ok"):
        out(f"  last fetch  : FAILED at {lf.get('time')}: {lf.get('error')}")
    if rt["state"] == "present" and rt.get("counters"):
        out("  dropped packets since load: " + ", ".join(f"{k}={v}" for k, v in sorted(rt["counters"].items())))
    if st["allowlist"]:
        out("  allowlist : " + ", ".join(st["allowlist"]))
    sd = st.get("systemd")
    if sd:
        out(f"  boot unit : {UNIT_BOOT}: {sd['boot_service']['enabled']}/{sd['boot_service']['active']}")
        t = sd["timer"]
        out(f"  timer     : {UNIT_TIMER}: {t['enabled']}/{t['active']}, next {t['next'] or 'n/a'}, last {t['last'] or 'n/a'}")
        out(f"  service   : {UNIT_UPDATE}: result={sd['update_service']['result']}")
    elif ctx.use_systemd:
        out("  systemd   : unavailable")
    return EXIT_OK


# internal service entry points -----------------------------------------------

def cmd_fetch(ctx: Context, args) -> int:
    counts = engine.fetch_stage(ctx.settings, ctx.state)
    log.info(f"fetched and validated data: {counts}")
    return EXIT_OK


def cmd_apply(ctx: Context, args) -> int:
    res = ctx.engine.apply_stage()
    log.info("apply: " + describe_result(res))
    return EXIT_OK


def cmd_load(ctx: Context, args) -> int:
    log.info(ctx.engine.load_stage())
    return EXIT_OK


def cmd_unload(ctx: Context, args) -> int:
    ctx.engine.unload_stage()
    log.info("table removed")
    return EXIT_OK


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=PROG, description="Block traffic to and from the IP allocations of configured countries (nftables).")
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="configuration file (default: %(default)s)")
    p.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help="state directory (default: %(default)s)")
    p.add_argument("--no-systemd", action="store_true", help="skip systemd integration (development/containers)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name, fn, help_, dry=False, hidden=False):
        sp = sub.add_parser(name, help=None if hidden else help_, description=help_)
        if dry:
            sp.add_argument("-n", "--dry-run", action="store_true", help="show what would happen; change nothing")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("install", cmd_install, "prepare directories, check compatibility, download data (does not enable)", dry=True)
    sp.add_argument("--no-fetch", action="store_true", help="skip the initial data download")
    sp = add("uninstall", cmd_uninstall, "remove the firewall table, disable units (keeps package files)", dry=True)
    sp.add_argument("--purge", action="store_true", help="also delete stored datasets and generations")
    add("enable", cmd_enable, "load the rules now and persistently (boot service + update timer)", dry=True)
    add("disable", cmd_disable, "remove the rules and disable boot service and timer", dry=True)
    add("update", cmd_update, "download, validate and apply fresh country data", dry=True)
    sp = add("status", cmd_status, "show installed/enabled/active state, dataset and timers")
    sp.add_argument("--json", action="store_true")
    sp = add("test", cmd_test, "read-only validation of config, data and firewall compatibility")
    sp.add_argument("--online", action="store_true", help="also download and validate fresh data (no changes)")
    sp = add("list", cmd_list, "print the installed (or --active) country ranges")
    sp.add_argument("--ipv4", action="store_true")
    sp.add_argument("--ipv6", action="store_true")
    sp.add_argument("--active", action="store_true", help="read the ranges loaded in the kernel (root)")
    sp.add_argument("--count", action="store_true", help="print counts only")
    sp.add_argument("--match", metavar="ADDRESS", help="report whether ADDRESS is covered")
    sp = add("check-config", cmd_check_config, "validate the configuration file")
    sp.add_argument("--show", action="store_true", help="print the effective settings")
    add("rollback", cmd_rollback, "return to the previous known-good generation", dry=True)
    for name, fn, h in (("fetch", cmd_fetch, "service stage: download+validate into staging (unprivileged)"),
                        ("apply", cmd_apply, "service stage: validate staged data and load it (root)"),
                        ("load", cmd_load, "service stage: load the current generation at boot"),
                        ("unload", cmd_unload, "service stage: remove the table")):
        add(name, fn, h, hidden=True)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = Context(args)
        return args.fn(ctx, args)
    except RuGeoblockError as exc:
        log.error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
