# Configuration

File: `/etc/geoblock/geoblock.conf`. Lines are `key = value`; `#` starts a comment. Unknown or duplicate
keys, control characters, world/group-writable files, symlinks and files over 64 KiB are rejected.
Nothing in the file is ever executed or passed to a shell. Validate with `geoblock check-config [--show]`.
Whether the policy is *enabled* is state (`enable`/`disable`), not a setting.

| Option | Default | Meaning |
|---|---|---|
| `provider` | `ipdeny` | data source (only `ipdeny` implemented) |
| `countries` | *(empty, required)* | comma-separated ISO 3166 alpha-2 codes, max 20. Nothing is blocked unless listed |
| `ipv4_url`, `ipv6_url` | provider default | https URL templates; must contain `{cc}` (replaced by the lowercase country code) |
| `ca_file` | system store | absolute path of a PEM bundle trusted instead of the system store |
| `ipv4`, `ipv6` | `yes` | filter that address family (not both `no`) |
| `block_input` | `yes` | drop packets whose source is listed |
| `block_output` | `yes` | block packets whose destination is listed |
| `block_forward` | `no` | also filter routed traffic (Docker, VMs, router mode) |
| `output_action` | `reject` | `reject` (immediate error) or `drop` (silent timeout) for outbound |
| `hook_priority` | `-10` | nftables hook priority, -100..100 (UFW/iptables use 0) |
| `allow_ipv4`, `allow_ipv6` | empty | exceptions: CIDRs matched before the country sets in geoblock's chains only |
| `connect_timeout` | `15` | seconds per socket operation (1-120) |
| `download_timeout` | `120` | seconds for one whole download (5-900) |
| `retries` | `3` | extra attempts on transient errors (0-5) |
| `retry_delay` | `5` | initial backoff seconds, doubling, capped at 120 (1-300) |
| `max_download_bytes` | `4194304` | response size cap (1 KiB-64 MiB) |
| `min_entries_v4`, `min_entries_v6` | `10`, `1` | minimum prefixes **per country and family**; smaller lists are rejected. Raise for large countries (ru: ≈2000 / ≈200) |
| `max_shrink_percent` | `50` | reject an update that removes more than this share of the previous entries (0-100; 100 disables) |
| `keep_generations` | `5` | known-good snapshots retained for rollback (2-50) |
| `log_level` | `info` | `error`, `warning`, `info`, `debug` |
| `service_user` | `geoblock` | user for the unprivileged download stage; empty = download as root (development only) |

## Exceptions (allowlist)

`allow_ipv4`/`allow_ipv6` accept an address before it reaches the country sets, per family and per
chain (input matches source, output matches destination). Precedence: loopback accept → allowlist
accept → country drop/reject. They only affect geoblock's chains; UFW still applies its own policy.
Exceptions appear in `geoblock status`. A wrong-family entry is a configuration error.

## Update schedule

Not a config option, because it belongs to systemd: see "Updates" in [installation.md](installation.md).

## Applying changes

Edit the file, run `geoblock check-config`, then `sudo geoblock update` (fetch + rebuild) or, for
ruleset-only options (`block_*`, `output_action`, `hook_priority`, allowlists), `sudo geoblock enable`
(re-renders from stored data). Changing `countries` requires `update`.
