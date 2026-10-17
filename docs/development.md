# Development

```bash
python3 -m pytest -q                 # everything runnable without root
python3 -m pytest tests/unit -q      # unit only
./scripts/check.sh                   # lint + consistency + units + tests (missing tools are SKIPPED)
make dist                            # source tarball
```

Requirements: Python ≥ 3.11, `pytest`, `ruff`, `openssl` (self-signed TLS for tests), `shellcheck`
(optional). Tests never touch the host firewall.

## Test layers

* `tests/unit`: CIDR validation, config, downloader (local TLS server with a throwaway CA), engine with
  a **fake `nft`** (failure injection: check failure, load failure, verification mismatch),
  locking, rollback, pruning, symlink/tamper defences, CLI behaviour.
* `tests/integration/scenario.py` (run by `test_netns.py`): real `nft`/`iptables-nft` inside
  `unshare --user --map-root-user --net`, with a veth pair to a peer namespace. Requires unprivileged
  user namespaces; skipped (visibly) otherwise. On Ubuntu 24.04 CI,
  `sysctl kernel.apparmor_restrict_unprivileged_userns=0` is needed.
* Not automated: real boot, live `ufw reload`, systemd units under real systemd, Docker, VPNs.
  Manual privileged checklist on a throwaway VM: install package → `geoblock enable` → reboot →
  `status` → `sudo ufw reload` → `nft list table inet geoblock` → `geoblock rollback` → `uninstall`.

## Code map

`config.py` strict parser · `cidr.py` validation · `download.py` bounded HTTPS · `provider.py` sources ·
`nftables.py` ruleset render/check/load/verify · `state.py` generations, locks · `engine.py` fetch/apply/
rollback · `preflight.py` compatibility · `systemd.py` · `cli.py`.

Add a provider: add a `Provider` entry in `provider.py` and its name to the `provider` enum in
`config.py`; the engine only sees validated datasets.

Packaging: `make dist`, then `makepkg` in `packaging/arch` (see [installation.md](installation.md)).
