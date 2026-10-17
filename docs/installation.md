# Installation and lifecycle

Installing the package or running `scripts/install.sh` **never changes firewall rules**. Activation is
a separate, explicit step (`geoblock enable`).

## States

| State | Meaning | Check |
|---|---|---|
| installed | files present, data directory exists | `geoblock status` → `installed` |
| data present | a validated generation exists (`geoblock install` / `update`) | `dataset` line |
| enabled | policy requested; persisted in `/var/lib/geoblock/state.json`; boot unit and timer enabled | `enabled` |
| active | the `inet geoblock` table is loaded in the kernel (needs root to read) | `active`, `in sync` |
| updated | last successful dataset publication | `last update` |

## Requirements

Arch-based system, `python` ≥ 3.11, `nftables`, `systemd`. UFW is optional. `firewalld` active → refused.

## From the package (Arch/CachyOS/Manjaro)

```bash
make dist
cd packaging/arch && cp ../../dist/geoblock-*.tar.gz . && makepkg -si
```
The `PKGBUILD` uses `sha256sums=('SKIP')` for the locally built tarball; pin a real checksum when you
publish releases. The post-install message repeats the activation steps. Removing the package runs
`geoblock uninstall` (removes only the `inet geoblock` table and disables the project's units);
`/etc/geoblock` and `/var/lib/geoblock` are kept.

## From a checkout

```bash
sudo ./scripts/install.sh --dry-run   # show actions
sudo ./scripts/install.sh             # idempotent; records installed paths in /var/lib/geoblock/manifest
```
Default prefix is `/usr/local` (units, sysusers and tmpfiles are read from there by systemd; the Arch package uses `/usr`). Options: `--prefix`, `--destdir` (staging root), `--no-system-setup`. An existing
`/etc/geoblock/geoblock.conf` is never overwritten. The manifest is written *before* copying files so
an interrupted install can still be removed; re-running the installer completes it.

## Activation

```bash
sudoedit /etc/geoblock/geoblock.conf      # countries = ru   (required; no default)
sudo geoblock check-config
sudo geoblock test                        # read-only
sudo geoblock install                     # fetch + validate first dataset (not enabled)
sudo geoblock enable --dry-run
sudo geoblock enable
```
`enable` runs the compatibility check, loads the rules atomically, verifies them, sets the enabled flag
and then runs `systemctl enable --now geoblock.service geoblock-update.timer`. If the systemd step
fails the command exits non-zero and says the rules are active but not persistent.

## Updates

`geoblock-update.timer`: `OnCalendar=daily`, `RandomizedDelaySec=1h`, `Persistent=true`. Change the
schedule with a drop-in (a reset line is required):

```bash
sudo systemctl edit geoblock-update.timer
# [Timer]
# OnCalendar=
# OnCalendar=*-*-* 04:30:00
```
Manual run: `sudo geoblock update`. Logs: `journalctl -u geoblock-update -u geoblock-apply -u geoblock`.

## Removal

```bash
sudo geoblock uninstall [--purge]       # table + unit enablement (+ stored data)
sudo ./scripts/uninstall.sh [--dry-run] [--purge-state] [--purge-config]
# or: sudo pacman -R geoblock
```
Files are removed only if listed in the manifest. Configuration is kept unless `--purge-config`.

## Paths

| Path | Purpose | Owner |
|---|---|---|
| `/usr/local/bin/geoblock`, `/usr/local/lib/geoblock/geoblock/` (`/usr/...` for the package) | code | root |
| `/etc/geoblock/geoblock.conf` | configuration (backup file in the package) | root |
| `/var/lib/geoblock/generations/<id>/` | immutable datasets + rulesets | root |
| `/var/lib/geoblock/{current,previous}` | pointers (symlinks) | root |
| `/var/lib/geoblock/staging/` | untrusted fetch output | `geoblock` user |
| `/var/lib/geoblock/{state.json,last_update.json,.state.lock,manifest}` | state | root |
| `<prefix>/lib/systemd/system/geoblock*.{service,timer}` | units | root |
| nftables table `inet geoblock` | the only firewall resource owned | kernel |
