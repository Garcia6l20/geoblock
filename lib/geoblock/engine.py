"""Update, activation and rollback logic.

Two stages with different privileges:
  fetch  - unprivileged: download, validate, write the *staging* directory.
  apply  - root: re-validate the staged data (it is untrusted), render the ruleset,
           check it with nft, load it atomically, verify it, then publish a generation.

Atomicity: `nft -f` replaces the table in one kernel transaction; renaming a
generation directory and swapping the `current` symlink are atomic file operations.
The sequence as a whole is *not* one transaction, so failures between steps are
handled explicitly (see apply_stage).
"""

import hashlib
import json
import os
import shutil
from dataclasses import dataclass

from . import __version__, cidr, log
from .config import RULESET_KEYS, Settings
from .download import fetch_text
from .errors import ConfigError, DataError, FirewallError, NotReadyError, PrivilegeError
from .nftables import Nft, parse_listing, render_ruleset, verify_listing
from .provider import resolve
from .state import Generation, State, atomic_write, dump_json, read_json, read_regular, utcnow

MAX_STAGED_META = 64 * 1024


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def enabled_families(settings: Settings) -> list:
    return [f for f, on in ((4, settings.ipv4), (6, settings.ipv6)) if on]


def min_entries(settings: Settings, family: int) -> int:
    return settings.min_entries_v4 if family == 4 else settings.min_entries_v6


def settings_snapshot(settings: Settings) -> dict:
    snap = {}
    for k in RULESET_KEYS:
        v = getattr(settings, k)
        snap[k] = [str(x) for x in v] if isinstance(v, tuple) else v
    return snap


@dataclass
class Staged:
    texts: dict  # (country, family) -> raw text
    fetched_at: str
    provider: str
    urls: dict
    digest: str


# ---------------------------------------------------------------- fetch stage

def require_countries(settings: Settings) -> None:
    if not settings.countries:
        raise ConfigError("no countries configured: set 'countries = xx' (ISO 3166 codes) in the configuration")


def merge_countries(settings: Settings, per_country: dict) -> dict:
    """per_country[(cc, family)] -> Dataset; returns {family: merged Dataset}."""
    return {fam: cidr.merge([per_country[(cc, fam)] for cc in settings.countries], fam)
            for fam in enabled_families(settings)}


def download_datasets(settings: Settings) -> tuple:
    """Download and validate every country/family. Returns (texts, datasets, provider).

    texts and datasets are keyed by (country, family).
    """
    require_countries(settings)
    provider = resolve(settings)
    texts, datasets = {}, {}
    for cc in settings.countries:
        for fam in enabled_families(settings):
            url = provider.url(fam, cc)
            log.info(f"downloading {cc.upper()} IPv{fam} list from {url}")
            text = fetch_text(
                url, ca_file=settings.ca_file, connect_timeout=settings.connect_timeout,
                total_timeout=settings.download_timeout, retries=settings.retries,
                retry_delay=settings.retry_delay, max_bytes=settings.max_download_bytes)
            try:
                ds = cidr.validate_dataset(text, fam, min_entries(settings, fam))
            except DataError as exc:
                raise DataError(f"{cc.upper()}: {exc}") from None
            log.info(f"{cc.upper()} IPv{fam}: {ds.count} unique prefixes ({len(ds.collapsed)} after merging, "
                     f"{ds.duplicates} duplicate lines)")
            texts[(cc, fam)], datasets[(cc, fam)] = text, ds
    return texts, datasets, provider


def fetch_stage(settings: Settings, state: State) -> dict:
    """Unprivileged stage: publish validated raw data into staging/ for the apply stage."""
    os.makedirs(state.staging, mode=0o755, exist_ok=True)
    status_path = os.path.join(state.staging, "fetch-status.json")
    with state.lock(state.staging_lock):
        try:
            texts, datasets, provider = download_datasets(settings)
        except Exception as exc:
            try:
                atomic_write(status_path, dump_json({"time": utcnow(), "ok": False, "error": str(exc)[:500]}))
            except OSError:
                pass
            raise
        files = {}
        for (cc, fam), text in texts.items():
            name = f"{cc}-ipv{fam}.zone"
            atomic_write(os.path.join(state.staging, name), text.encode())
            files[name] = sha256(text)
        # fetch.json is written last: apply refuses staged data without a matching manifest.
        meta = {"time": utcnow(), "provider": provider.name, "files": files,
                "urls": {f"{cc}-ipv{f}": provider.url(f, cc) for cc, f in texts},
                "countries": list(settings.countries), "tool_version": __version__}
        atomic_write(os.path.join(state.staging, "fetch.json"), dump_json(meta))
        atomic_write(status_path, dump_json({"time": meta["time"], "ok": True}))
    return {f"{cc}-ipv{f}": ds.count for (cc, f), ds in datasets.items()}


# ---------------------------------------------------------------- apply stage

def read_staged(settings: Settings, state: State) -> Staged | None:
    """Read staging/ defensively: it is written by an unprivileged user."""
    try:
        dfd = os.open(state.staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DataError(f"can not open staging directory: {exc.strerror}") from None
    try:
        try:
            raw = read_regular("fetch.json", MAX_STAGED_META, dir_fd=dfd)
        except FileNotFoundError:
            return None
        try:
            meta = json.loads(raw)
            files = meta["files"]
            if not isinstance(files, dict):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            raise DataError("staged manifest fetch.json is malformed") from None
        texts = {}
        for cc in settings.countries:
            for fam in enabled_families(settings):
                name = f"{cc}-ipv{fam}.zone"
                if name not in files:
                    # Staged data was fetched for a different configuration: ignore it.
                    return None
                try:
                    text = read_regular(name, settings.max_download_bytes, dir_fd=dfd).decode()
                except FileNotFoundError:
                    raise DataError(f"staged file {name} is missing") from None
                except UnicodeDecodeError:
                    raise DataError(f"staged file {name} is not valid UTF-8") from None
                if sha256(text) != files[name]:
                    raise DataError(f"staged file {name} does not match its manifest (concurrent write?)")
                texts[(cc, fam)] = text
    finally:
        os.close(dfd)
    digest = sha256("".join(f"{cc}-{fam}:{files[f'{cc}-ipv{fam}.zone']};" for cc, fam in sorted(texts)))
    return Staged(texts, str(meta.get("time", "")), str(meta.get("provider", "")),
                  dict(meta.get("urls", {})), digest)


def _datasets_from_generation(settings: Settings, gen: Generation) -> dict:
    out = {}
    for fam in enabled_families(settings):
        name = f"ipv{fam}.txt"
        try:
            text = gen.read(name)
        except FileNotFoundError:
            raise NotReadyError(f"the current generation has no IPv{fam} data; run 'geoblock update'") from None
        expected = gen.meta.get(f"ipv{fam}", {}).get("sha256")
        if expected and sha256(text) != expected:
            raise DataError(f"{name} in generation {gen.id} fails its integrity check")
        out[fam] = cidr.validate_dataset(text, fam, 1)
    return out


@dataclass
class ApplyResult:
    changed: bool
    activated: bool
    generation: str
    counts: dict
    message: str


class Engine:
    def __init__(self, settings: Settings, state: State, nft: Nft, require_root: bool = True):
        self.require_root = require_root
        self.s = settings
        self.state = state
        self.nft = nft

    # -- helpers -------------------------------------------------------------
    def _require_root(self) -> None:
        if self.require_root and os.geteuid() != 0:
            raise PrivilegeError("this operation requires root")

    def _render(self, datasets: dict) -> str:
        v4 = datasets[4].collapsed if 4 in datasets else ()
        v6 = datasets[6].collapsed if 6 in datasets else ()
        return render_ruleset(self.s, v4, v6)

    def _verify_runtime(self, gen: Generation, datasets: dict | None = None) -> None:
        datasets = datasets or _datasets_from_generation(self.s, gen)
        v4 = datasets[4].collapsed if 4 in datasets else ()
        v6 = datasets[6].collapsed if 6 in datasets else ()
        verify_listing(self.nft.list_table(), self.s, v4, v6)

    def runtime_in_sync(self, gen: Generation) -> bool:
        try:
            self._verify_runtime(gen)
            return True
        except (FirewallError, DataError, NotReadyError):
            return False

    def _load_runtime(self, ruleset: str, restore: str | None, verify) -> None:
        """Atomically load `ruleset`; if verification fails put `restore` back (or remove)."""
        self.nft.load(ruleset)  # all-or-nothing: on failure the old table is untouched
        try:
            verify()
        except Exception:
            log.error("verification of the loaded rules failed; restoring the previous rules")
            try:
                if restore:
                    self.nft.load(restore)
                else:
                    self.nft.delete_table()
            except FirewallError as exc:
                log.error(f"restoring the previous rules failed: {exc}")
            raise

    # -- apply ---------------------------------------------------------------
    def apply_stage(self, activate: bool = False, dry_run: bool = False,
                    use_staged: bool = True) -> ApplyResult:
        """Build, check, load and publish a generation from staged (or current) data."""
        require_countries(self.s)
        if not dry_run:
            self._require_root()
        os.makedirs(self.state.dir, exist_ok=True)
        os.makedirs(self.state.staging, mode=0o755, exist_ok=True)
        with self.state.lock(self.state.staging_lock), self.state.lock():
            try:
                return self._apply_locked(activate, dry_run, use_staged)
            except Exception as exc:
                if not dry_run:
                    self.state.record_attempt(False, str(exc))
                raise

    def _apply_locked(self, activate: bool, dry_run: bool, use_staged: bool) -> ApplyResult:
        cur = self.state.current()
        enabled = self.state.is_enabled() or activate
        staged = read_staged(self.s, self.state) if use_staged else None
        cur_digest = cur.meta.get("source_digest") if cur else None
        take_staged = staged is not None and staged.digest != cur_digest

        if take_staged:
            per_country = {}
            for (cc, fam), text in staged.texts.items():
                try:
                    per_country[(cc, fam)] = cidr.validate_dataset(text, fam, min_entries(self.s, fam))
                except DataError as exc:
                    raise DataError(f"{cc.upper()}: {exc}") from None
            datasets = merge_countries(self.s, per_country)
            if cur:
                for fam, ds in datasets.items():
                    old = cur.meta.get(f"ipv{fam}", {}).get("count", 0)
                    cidr.check_shrink(ds.count, old, self.s.max_shrink_percent, fam)
            source = {"source_digest": staged.digest, "fetched_at": staged.fetched_at,
                      "provider": staged.provider, "urls": staged.urls}
        elif cur:
            if tuple(cur.meta.get("countries", ())) != self.s.countries:
                raise NotReadyError("the configured countries differ from the installed dataset; "
                                    "run 'geoblock update'")
            datasets = _datasets_from_generation(self.s, cur)
            for fam, ds in datasets.items():
                if ds.count < min_entries(self.s, fam):
                    raise DataError(f"IPv{fam} data has {ds.count} entries, below the configured minimum")
            source = {k: cur.meta.get(k) for k in ("source_digest", "fetched_at", "provider", "urls")}
        else:
            raise NotReadyError("no dataset available; run 'geoblock update' first")

        ruleset = self._render(datasets)
        self.nft.check(ruleset)
        counts = {f"ipv{f}": datasets[f].count for f in datasets}
        ruleset_hash = sha256(ruleset)

        unchanged = (cur is not None and not take_staged
                     and cur.meta.get("ruleset_sha256") == ruleset_hash)
        if dry_run:
            what = "no change" if unchanged else "would publish a new generation"
            return ApplyResult(False, False, cur.id if cur else "", counts, f"dry run: {what}; ruleset passes nft -c")

        if unchanged:
            if enabled and not self.runtime_in_sync(cur):
                log.info("runtime rules differ from the current generation; reloading")
                self._load_runtime(cur.read("ruleset.nft"), None, lambda: self._verify_runtime(cur))
                if activate:
                    self.state.set_enabled(True)
                self.state.record_attempt(True, "runtime rules restored", generation=cur.id)
                return ApplyResult(True, True, cur.id, counts, "runtime rules reloaded")
            if activate:
                self.state.set_enabled(True)
            self.state.record_attempt(True, "dataset unchanged", generation=cur.id)
            return ApplyResult(False, enabled, cur.id, counts, "dataset and settings unchanged")

        meta = {
            "created": utcnow(), "tool_version": __version__, **source,
            "countries": list(self.s.countries),
            "settings": settings_snapshot(self.s), "ruleset_sha256": ruleset_hash,
            **{f"ipv{f}": {"count": ds.count, "collapsed": len(ds.collapsed),
                            "duplicates": ds.duplicates,
                            "sha256": sha256(cidr.render_lines(ds.collapsed))}
               for f, ds in datasets.items()},
        }
        files = {"ruleset.nft": ruleset}
        for f, ds in datasets.items():
            files[f"ipv{f}.txt"] = cidr.render_lines(ds.collapsed)
        gen = self.state.create_generation(files, meta)
        try:
            if enabled:
                restore = cur.read("ruleset.nft") if cur and self.state.is_enabled() else None
                self._load_runtime(ruleset, restore, lambda: self._verify_runtime(gen, datasets))
            # Only now does the boot-time pointer move: a crash before this line leaves
            # the old known-good generation as `current`.
            self.state.publish(gen)
            if activate:
                self.state.set_enabled(True)
        except BaseException:
            shutil.rmtree(gen.path, ignore_errors=True)
            raise
        self.state.prune(self.s.keep_generations)
        self.state.record_attempt(True, "generation published", generation=gen.id, counts=counts)
        return ApplyResult(True, enabled, gen.id, counts, "generation published")

    # -- boot / teardown --------------------------------------------------------
    def load_stage(self) -> str:
        """Boot-time load of the current known-good generation."""
        self._require_root()
        with self.state.lock(wait=30):
            if not self.state.is_enabled():
                return "not enabled; nothing to load"
            cur = self.state.current()
            if cur is None:
                raise NotReadyError("enabled but no current generation exists")
            ruleset = cur.read("ruleset.nft")
            if sha256(ruleset) != cur.meta.get("ruleset_sha256"):
                raise DataError(f"ruleset of generation {cur.id} fails its integrity check")
            self._load_runtime(ruleset, None, lambda: self._verify_runtime(cur))
            return f"loaded generation {cur.id}"

    def unload_stage(self) -> None:
        self._require_root()
        with self.state.lock(wait=30):
            self.nft.delete_table()

    def disable(self, dry_run: bool = False) -> str:
        if dry_run:
            return "dry run: would delete the geoblock table and clear the enabled flag"
        self._require_root()
        with self.state.lock(wait=30):
            self.nft.delete_table()
            self.state.set_enabled(False)
        return "table removed and policy disabled"

    def rollback(self, dry_run: bool = False) -> str:
        prev = self.state.previous()
        if prev is None:
            raise NotReadyError("no previous generation is available; nothing to roll back to")
        datasets = _datasets_from_generation(self.s, prev)
        ruleset = prev.read("ruleset.nft")
        if sha256(ruleset) != prev.meta.get("ruleset_sha256"):
            raise DataError(f"ruleset of generation {prev.id} fails its integrity check")
        self.nft.check(ruleset)
        if dry_run:
            return f"dry run: would roll back to generation {prev.id}"
        self._require_root()
        with self.state.lock(wait=30):
            cur = self.state.current()
            if self.state.is_enabled():
                restore = cur.read("ruleset.nft") if cur else None
                self._load_runtime(ruleset, restore, lambda: self._verify_runtime(prev, datasets))
            self.state.swap_back()
            self.state.record_attempt(True, f"rolled back to {prev.id}", generation=prev.id)
        return f"rolled back to generation {prev.id}"

    # -- inspection ------------------------------------------------------------
    def runtime_info(self) -> dict:
        """Return {'state': ..., 'counters': ...} describing the installed table."""
        try:
            listing = self.nft.list_table()
        except FirewallError as exc:
            return {"state": "unknown", "detail": str(exc)}
        if listing is None:
            return {"state": "absent"}
        parsed = parse_listing(listing)
        counters = {k: v["packets"] for k, v in parsed["rules"].items() if k.endswith(("-v4", "-v6")) or "-src-" in k or "-dst-" in k}
        return {"state": "present", "counters": counters,
                "chains": sorted(parsed["chains"]), "set_ranges": {k: len(v) for k, v in parsed["sets"].items()}}


def load_fetch_status(state: State):
    return read_json(os.path.join(state.staging, "fetch-status.json"))
