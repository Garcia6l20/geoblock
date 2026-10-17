# Rollback and manual recovery

## Automatic

* A failed update never changes the loaded rules or `current`.
* If rules were loaded but verification failed, the previous ruleset is loaded back (or the table is
  deleted if none existed) before the error is reported.

## `geoblock rollback`

```bash
sudo geoblock rollback --dry-run
sudo geoblock rollback
```
Validates the previous generation (SHA-256, `nft -c`), loads it (if enabled), then swaps the
`current`/`previous` pointers. Running it twice returns to where you started. With no previous
generation it exits 6 and explains why. Rollback restores the stored *snapshot*, including the
settings that were in effect when it was built.

## Manual recovery without the tool

```bash
sudo nft delete table inet geoblock                 # stop filtering immediately, touches nothing else
sudo systemctl disable --now geoblock.service geoblock-update.timer
ls /var/lib/geoblock/generations/                   # pick a generation
sudo ln -sfn generations/<id> /var/lib/geoblock/current   # point boot at a known-good one
sudo nft -f /var/lib/geoblock/generations/<id>/ruleset.nft # load it
```
To reset all project state: `sudo geoblock uninstall --purge`.
UFW is never part of recovery because geoblock never modifies it.

## Locked out?

Existing connections to listed countries are cut on `enable`. From a console: `sudo nft delete table inet geoblock`.
