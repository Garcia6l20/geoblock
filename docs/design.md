# Design

## Goals and non-goals

Block inbound sources and outbound destinations in the IPv4/IPv6 allocations of explicitly configured countries, coexist with the
existing firewall, survive reboot and UFW reloads, update itself safely, and be inspectable.
Non-goals: other countries, attribution, intrusion detection, replacing UFW.

## Architecture in one picture

```
 timer ──> geoblock-update.service   (user geoblock, no capabilities, network)
              download ─> validate ─> /var/lib/geoblock/staging/   (untrusted output)
              └ OnSuccess ─> geoblock-apply.service (root, CAP_NET_ADMIN only, no network)
                    re-validate staged data ─> render ruleset ─> nft -c ─> generation dir
                    ─> nft -f (atomic) ─> verify listing ─> flip `current` symlink
 boot ──> geoblock.service  (oneshot): nft -f generations/<current>/ruleset.nft
```

## Decisions

### 1. Firewall backend: a dedicated native nftables table

Alternatives evaluated:

| Option | Verdict |
|---|---|
| UFW rules (`ufw deny from ...`) | One rule per prefix (≈10,800), each a chain entry evaluated linearly; `ufw reload` re-creates them slowly; the tool would have to own entries inside the user's UFW rule files, risking collisions with user rules and violating "never modify UFW configuration". Rejected. |
| Narrow hook via `before.rules`/`after.rules` or `ipset` | `before.rules` is a user-owned UFW file; editing it is a UFW configuration change and is overwritten/diverges on `ufw reset`. ipset is legacy and needs the iptables-legacy-era toolchain. Rejected. |
| **Own table `inet geoblock`** | Chosen. |

Why the table approach is safe next to UFW: nftables evaluates **every base chain registered on a
hook**, in priority order, and a packet is dropped if *any* of them drops it; an `accept` in one
chain only ends that chain. UFW on CachyOS uses `iptables-nft`, which creates tables such as
`ip filter`/`ip6 filter` with hooks at priority 0. A separate `inet` table therefore (a) can not be
overridden by a UFW `allow` rule, (b) is not touched by `ufw reload`/`iptables-restore`, which only
replace UFW's own tables, and (c) needs no UFW cooperation. The reverse also holds: our `accept`
(loopback, allowlist) never exempts traffic from UFW's policy.

Hooks used: `input`, `output` (and optionally `forward`) at priority **-10**: after connection
tracking (-200) and DNAT (-100), before UFW's filter chains (0). Order does not change the final verdict
(any drop wins) but dropping early avoids pointless work in later chains.

Per-packet cost: each family has one **interval set** (`flags interval`), looked up in
O(log n) regardless of the ≈8,700 IPv4 / ≈2,200 IPv6 prefixes. The set is one rule per
chain, not one rule per prefix. There is no `ct state` match: the check applies to every packet.

### 2. Verdicts

Inbound: `drop` (do not answer scanners). Outbound: `reject` by default so local programs fail
immediately instead of hanging (`output_action = drop` for silent). Forward (routed/container
traffic): off by default because enabling it can break Docker/VM networks; `drop` when enabled.
`iifname "lo" accept` / `oifname "lo" accept` is the first rule of each chain, so a poisoned or
misconfigured list can never cut loopback. The dataset validator additionally refuses any list that
overlaps loopback, private, link-local, CGNAT, multicast or reserved space.

### 3. Established connections

No connection-tracking exemption: enabling the policy cuts existing connections to and from
listed addresses on their next packet. Verified in the namespace scenario. Rationale: a security
policy that spares connections an attacker already opened is weak; the cost is one dropped session
if you are connected through a listed address.

### 4. Language: Python 3 (stdlib only) + Bash

CIDR validation, merging, JSON handling, flock and symlink-safe file I/O are error-prone in shell.
Python's `ipaddress` gives strict parsing. Bash is used only for the installer scripts. No third-party
dependencies, no database, no daemon.

### 5. Two-stage update with privilege separation

Downloading and parsing untrusted network data is the risky part, so it runs as the unprivileged
`geoblock` user with no capabilities. The root stage has no network access
(`IPAddressDeny=any`), reads staging **without following symlinks**, bounded in size, and **re-validates
everything** (staged files are untrusted even though our own code produced them). The root service holds
only `CAP_NET_ADMIN` and `CAP_DAC_READ_SEARCH`.

### 6. Generations instead of in-place edits

Each applied dataset becomes an immutable directory `generations/<id>/` (`ipv4.txt`, `ipv6.txt`,
`ruleset.nft`, `meta.json` with SHA-256s). `current` and `previous` are symlinks swapped with
atomic renames. Boot loads `current/ruleset.nft` after an integrity check. Rollback swaps the pointers.
Retention is `keep_generations`.

### 7. What is and is not atomic

* `nft -f` with the `add table; delete table; table {...}` header replaces the project table in **one
  netlink transaction**: no packet sees a half-loaded table; if nft rejects the script the old table is
  untouched.
* Renaming a generation directory and replacing a symlink are atomic file operations.
* The *whole update is not one transaction*: kernel state and the on-disk pointer are two systems. The
  order is chosen so every crash window is safe:
  1. build generation dir (not yet referenced) → `nft -c` check;
  2. `nft -f` load, then verify the kernel listing against the generated data; on verification
     failure the previous ruleset is loaded back (or the table deleted if there was none);
  3. only then flip `current`. A crash between 2 and 3 leaves the kernel on the new rules and `current` on
     the old known-good generation; the next boot loads the old (slightly stale, never inconsistent)
     policy and the next update repairs it. A failure to flip the pointer is reported as an error.
* Fail-open at boot: if `current` is corrupt, the boot unit fails loudly and no rules load rather
  than leaving the machine half-filtered. `status` shows `enabled: yes, active: no`.

### 8. Exceptions

`allow_ipv4` / `allow_ipv6` are the only exception mechanism. They are explicit CIDR lists in the
root-owned config, matched before the country sets in the project's chains only, shown by `status`, and
validated per family. They exempt traffic from *this* filter, never from UFW.

### 9. Configurable countries, no default

`countries = ru, nl` (ISO 3166 alpha-2, validated, at most 20). The default is empty and every
command that needs data refuses to run until at least one country is named, so nothing is ever blocked
silently. Each country/family is downloaded and validated on its own (minimum size, protected ranges);
one bad list aborts the whole update. The validated lists are merged into one set per family. If the
configured countries differ from the installed dataset, the root stage refuses to reuse it and asks for
`geoblock update`.

## Known limitations

See [threat-model.md](threat-model.md). Additionally: updates replace the whole table, so the
packet counters reset; `geoblock.service` removes the table when stopped (`systemctl restart`
leaves a brief unfiltered gap; use `reload`); only the single `ipdeny` provider is implemented
(adding one is an entry in `provider.py`).
