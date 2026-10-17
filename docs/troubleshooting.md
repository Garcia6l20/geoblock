# Troubleshooting

| Symptom | Check / fix |
|---|---|
| `enable` refuses: "no countries configured" | set `countries = xx` in the config |
| `enable` refuses: firewalld active | stop/disable firewalld or do not use geoblock; not verified |
| `status`: enabled yes, active no | boot load failed or `nftables` was reloaded: `journalctl -u geoblock`, then `sudo systemctl reload geoblock` |
| `status`: in sync NO | something replaced the table; `sudo geoblock update` or `enable` rebuilds it |
| Update fails, exit 5 | `journalctl -u geoblock-update -u geoblock-apply`; common causes: no network, certificate error (`ca_file`), list below `min_entries_*`, shrink protection |
| "protected range" error | provider returned private/loopback/reserved space; do not override, investigate the provider |
| Lock busy (exit 75) | another run holds `/var/lib/geoblock/.state.lock`; wait or check `systemctl status geoblock-*` |
| A needed site is unreachable | `geoblock list --match IP`; add a narrow `allow_ipv4/6` exception (explicit and visible in `status`) |
| Docker containers unaffected | by design; set `block_forward = yes` and `sudo geoblock enable` |
| VPN stops connecting | the VPN endpoint is in a blocked country; exempt that single address via `allow_ipv4/6` |
| UFW rules look unchanged | expected: `sudo ufw status` / `iptables -S` are unaffected; geoblock lives in `nft list table inet geoblock` |
| Packets still dropped after `disable` | `sudo nft list ruleset`; those are other firewalls, not geoblock |

Diagnostics: `geoblock status --json`, `sudo geoblock test --online`, `sudo nft list table inet geoblock`
(per-rule counters show what is being dropped), `systemctl list-timers geoblock-update.timer`.
Conflicting managers: `systemctl is-active firewalld ufw nftables docker`.
