# Threat model

## Purpose

Reduce exposure to, and egress toward, IP space allocated to countries you choose. It is **not** an
attribution system: an address in a country's allocation says nothing reliable about who is behind it.

## In scope

* Unsolicited inbound connections and scans from listed ranges.
* Software on this host reaching listed ranges (outbound), e.g. telemetry, command-and-control.
* Safe handling of untrusted downloaded data and untrusted staging files.
* Not weakening existing firewall policy; not locking the host out of loopback/LAN.

## Out of scope / limitations

* VPNs, proxies, Tor, compromised or rented hosts outside the listed countries bypass the filter.
* Allocation data (RIR delegations aggregated by the provider) can be stale or inaccurate; addresses move.
* Legitimate services hosted in listed ranges (including CDNs, package mirrors, APIs) become unreachable.
* Outbound blocking can interfere with VPN endpoints, repositories and other software.
* It does not stop malicious local code from running, and it is no substitute for AUR package
  inspection, least privilege, updates, or default-deny inbound filtering (keep UFW).
* A local root user can remove the table. Hostile processes with CAP_NET_ADMIN are out of scope.

## Trust assumptions

* **Provider**: IPdeny's aggregated zone files are trusted for content. Their terms: free use,
  provided without warranty ([copyright](https://www.ipdeny.com/copyright.php)); fair-use limits of
  5000 downloads/day/IP ([usage limits](https://www.ipdeny.com/usagelimits.php), page dated 2022-09).
  Two downloads per country per day is far below this. A compromised provider could publish a list that
  blocks unrelated ranges; mitigations: strict syntax validation, rejection of loopback/private/
  link-local/multicast/reserved overlaps and of prefixes shorter than /8 (IPv4) or /16 (IPv6),
  per-country minimum sizes, and `max_shrink_percent`. It can not make the tool run code. It *can*
  cause denial of service toward legitimate public ranges; that is accepted residual risk.
* **Transport**: HTTPS with the system trust store (TLS ≥ 1.2), certificate verification mandatory,
  redirects only to https, bounded size/time/retries. There is no signature on the data itself.
* **Local config**: root-owned, strictly parsed, no command injection surface (no shell, no
  `eval`, no user-supplied command or binary paths).
* **Staging directory**: written by the unprivileged `geoblock` user and therefore treated as
  untrusted by the root stage: no symlink following, size caps, SHA-256 manifest check, complete
  re-validation before use.

## Failure behaviour

* Failed or invalid update: previous rules and data stay active (exit 5).
* Failed load: the kernel table is untouched (atomic) or the previous ruleset is restored.
* Corrupt `current` at boot: nothing is loaded and the boot unit fails loudly (fail-open for
  traffic, visible in `status`). Fail-closed would require inventing a policy that blocks everything.
* Network outage during update: the previous policy stays; the timer retries next cycle.
