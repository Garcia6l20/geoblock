# Firewall backends and compatibility

## Selected backend: native nftables table `inet geoblock`

See [design.md](design.md) for why this beats UFW rules and `before.rules` edits.

## What was verified on the development machine (CachyOS, no root)

* UFW 0.36.2 installed and active; `iptables --version` reports `iptables v1.8.13 (nf_tables)`, so UFW
  rules live in iptables-nft tables (`ip filter`, `ip6 filter`, ...). `/etc/default/ufw`:
  default input DROP, output ACCEPT, forward DROP, `IPV6=yes`.
* `nftables.service` is disabled and `/etc/nftables.conf` has no `flush ruleset`.
* In a disposable namespace, with the real `nft` and `iptables-nft`:
  * iptables-nft rules and an unrelated `inet` table were byte-identical (ignoring counters) after
    enable, update, rollback, disable and uninstall;
  * an `iptables-save` / flush / `iptables-restore` cycle (what `ufw reload` does to UFW's tables)
    left the `inet geoblock` table loaded and filtering;
  * IPv4 and IPv6, inbound and outbound, matching and non-matching traffic; established connections cut.

## Not verified (theoretical)

| Setup | Status |
|---|---|
| Real `ufw reload` / `systemctl restart ufw` on a live host | **not run** (needs root). By design they only rewrite UFW's tables |
| UFW with `iptables-legacy` | not tested; legacy and nft hooks are evaluated independently |
| `firewalld` | **refused** by `enable` (coexistence not verified) |
| `nftables.service` with `flush ruleset` | detected, warned. A reload of that service removes our table; `geoblock.service` is ordered `After=nftables.service`, but run `systemctl reload geoblock` after reloading nftables |
| Docker/Podman | not tested; forwarded container traffic is only filtered with `block_forward = yes` |
| VPN clients (WireGuard, OpenVPN) | not tested; outbound rules see the real post-NAT destination, so a VPN endpoint inside a blocked country is blocked |
| Manjaro / Arch | not tested |

## Inspecting the effective rules

```bash
sudo nft list table inet geoblock            # rules, counters, sets
sudo nft list ruleset | grep -n 'hook\|table' # all base chains and their priorities
sudo geoblock list --active --count          # ranges loaded in the kernel
geoblock status                              # in sync with the stored generation?
sudo iptables -S ; sudo ufw status verbose   # UFW's own view (unchanged by geoblock)
```

## Detected conflicts (`geoblock test`)

`firewalld` active (error); nft missing or kernel without nf_tables (error); `nftables.service` with
`flush ruleset`, shorewall, ferm (warning); Docker/Podman, VPN interfaces, UFW inactive,
iptables-legacy (info).
