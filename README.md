# geoblock

Block network traffic to and from the IPv4 and IPv6 address ranges allocated to the countries **you
list** (`countries = ru`, ...), on Linux, using a dedicated **nftables** table (`inet geoblock`) that sits
beside your existing firewall. Built for CachyOS with UFW; also intended for Arch Linux and Manjaro.
No country is blocked by default: you must name each one in the configuration.

It does **not** replace, flush or reconfigure UFW. It owns exactly one nftables table and removes
only that table.

> **Limits, up front.** This reduces exposure to the IP allocations of the countries you list; it is not
> attribution and not a security boundary on its own. VPNs, proxies, compromised hosts and servers outside
> the listed countries bypass it; allocation data can be stale or wrong; legitimate services hosted there
> become unreachable; outbound
> blocking can break software you depend on. See [docs/threat-model.md](docs/threat-model.md).

## Supported systems and backends

| | Status |
|---|---|
| CachyOS (primary) | developed and tested here (see "Tested" below) |
| Arch Linux, Manjaro | expected to work (same packages); **not tested** |
| Firewall frontend | UFW (any backend) or none. UFW is detected, never modified |
| Backend | native nftables table. `firewalld` is refused (coexistence not verified) |

Details and the evidence behind them: [docs/firewall-backends.md](docs/firewall-backends.md).

## Install

```bash
# One line (downloads the repo tarball over HTTPS, installs files only; read install.sh first if you prefer):
curl -fsSL https://raw.githubusercontent.com/Garcia6l20/geoblock/refs/heads/main/install.sh | bash
# options: ... | bash -s -- --dry-run      pin a version: GEOBLOCK_REF=v0.1.0 ... | bash

# From a source checkout (installs files and systemd units only; no firewall change):
sudo ./scripts/install.sh

# Or build the Arch package:
make dist && cd packaging/arch && cp ../../dist/geoblock-*.tar.gz . && makepkg -si
```

Installing never activates the firewall. See [docs/installation.md](docs/installation.md).

## First activation

```bash
sudoedit /etc/geoblock/geoblock.conf   # set: countries = ru   (comma-separated ISO codes)
sudo geoblock test        # read-only: config, firewall compatibility, nft ruleset check
sudo geoblock install     # download + validate the first dataset (does NOT enable it)
sudo geoblock enable --dry-run
sudo geoblock enable      # load rules now, enable boot service and daily update timer
geoblock status
```

Established connections to/from listed addresses are cut immediately on `enable`
(there is no connection-tracking exemption). Make sure you are not connected to the machine
through an address of a listed country before enabling.

## CLI

| Command | Root | What it does |
|---|---|---|
| `install [--no-fetch] [-n]` | yes | create directories, check compatibility, fetch + validate data. Does not enable |
| `enable [-n]` | yes | load the rules, enable `geoblock.service` (boot) and `geoblock-update.timer` |
| `disable [-n]` | yes | delete the table, disable the boot service and timer |
| `update [-n]` | yes (dry-run: no) | download, validate, apply (if enabled) a fresh dataset |
| `status [--json]` | no (runtime view needs root) | installed / enabled / active / in sync, dataset, last update, timers |
| `test [--online]` | no | read-only validation; never changes the active policy |
| `list [--active] [--ipv4\|--ipv6] [--count] [--match IP]` | no (`--active`: yes) | installed or kernel-loaded ranges |
| `check-config [--show]` | no | validate `/etc/geoblock/geoblock.conf` |
| `rollback [-n]` | yes | return to the previous known-good generation |
| `uninstall [--purge] [-n]` | yes | remove the table and disable units; `--purge` also deletes stored data |

Global options: `--config FILE`, `--state-dir DIR`, `--no-systemd`, `-v`. `-n/--dry-run` shows what
would happen and changes nothing. Exit codes: 0 ok, 1 failure, 2 usage/config error, 3 compatibility
refusal, 4 not root, 5 update/validation/firewall failure (previous policy retained), 6 no data /
nothing to roll back, 75 another operation holds the lock.

*Installed*, *enabled*, *active* and *updated* are different things and `status` reports them
separately: installed = files + data present; enabled = policy requested and persisted for reboot;
active = rules currently loaded in the kernel; updated = last successful dataset publication.

## Configuration

`/etc/geoblock/geoblock.conf`, `key = value`, strictly validated. Defaults are sensible
(IPv4+IPv6, block inbound and outbound, reject outbound). Every option is documented in
[docs/configuration.md](docs/configuration.md) and the commented example `config/geoblock.conf.example`.

## Automatic updates

`geoblock-update.timer` runs daily with a random delay of up to one hour and `Persistent=true`
(catches up after the machine was off). The update is two systemd services: an unprivileged
download-and-validate stage and a minimal-capability apply stage. A failed update never weakens or
removes the active policy. Logs: `journalctl -u geoblock-update -u geoblock-apply -u geoblock`.

## Status and diagnostics

```bash
geoblock status            # human readable
sudo geoblock list --active --count
sudo nft list table inet geoblock
```

Troubleshooting (UFW, VPNs, Docker, conflicts): [docs/troubleshooting.md](docs/troubleshooting.md).

## Rollback and removal

```bash
sudo geoblock rollback       # previous known-good generation
sudo geoblock disable        # stop filtering, keep everything installed
sudo geoblock uninstall      # remove table + units' enablement
sudo ./scripts/uninstall.sh     # also remove installed files (or: pacman -R geoblock)
```

See [docs/rollback.md](docs/rollback.md) for manual recovery without the tool.

## Tested vs. not tested

Run on the development machine (CachyOS, kernel 7.2, nftables 1.1.7, iptables-nft 1.8.13, UFW 0.36.2
installed, Python 3.14) **without root**:

* Tested: unit tests; end-to-end filtering with the real `nft` inside a disposable user+network
  namespace (IPv4/IPv6 inbound/outbound, established connections, reload simulation via
  `iptables-restore`, failed updates, rollback, reboot simulation, allowlist, uninstall, foreign tables
  untouched); installer/uninstaller into a staging root; `makepkg` package build; `systemd-analyze verify`.
* **Not tested**: real boot with the systemd units running, `ufw reload`/restart against a live UFW,
  Docker, VPN clients, firewalld, iptables-legacy, Manjaro/Arch, `namcap`. See
  [docs/development.md](docs/development.md) for how to run the privileged checks yourself.

## Documentation

[design](docs/design.md) · [installation](docs/installation.md) · [configuration](docs/configuration.md) ·
[firewall backends](docs/firewall-backends.md) · [threat model](docs/threat-model.md) ·
[rollback](docs/rollback.md) · [troubleshooting](docs/troubleshooting.md) · [development](docs/development.md)

Author: Garcia Sylvain · Repository: <https://github.com/G6L20/geoblock> · Licence: MIT. Data: IPdeny aggregated country lists (see the trust notes in the threat model).
