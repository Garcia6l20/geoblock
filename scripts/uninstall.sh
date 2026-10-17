#!/usr/bin/env bash
# Remove a geoblock installation made by scripts/install.sh.
# Only paths recorded in /var/lib/geoblock/manifest are removed. Unrelated firewall
# rules are never touched: the only firewall resource owned by the project is the
# nftables table "inet geoblock".
set -euo pipefail

DRY_RUN=0
PURGE_STATE=0
PURGE_CONFIG=0
DESTDIR=
PREFIX=/usr/local
SYSCONFDIR=/etc

usage() {
    cat <<USAGE
Usage: $0 [--dry-run] [--purge-state] [--purge-config] [--prefix DIR] [--destdir DIR]
  --dry-run       show what would be removed, change nothing
  --purge-state   also delete /var/lib/geoblock (datasets, generations)
  --purge-config  also delete $SYSCONFDIR/geoblock/ (kept by default)
  --prefix DIR    prefix used at install time (default: /usr/local)
  --destdir DIR   operate on a staging root (skips systemd and firewall steps)
USAGE
}

while [ $# -gt 0 ]; do
    case $1 in
        --dry-run) DRY_RUN=1 ;;
        --purge-state) PURGE_STATE=1 ;;
        --purge-config) PURGE_CONFIG=1 ;;
        --prefix) PREFIX=${2:?--prefix needs a value}; shift ;;
        --destdir) DESTDIR=${2:?--destdir needs a value}; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say() { printf '%s\n' "$*"; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then say "[dry-run] $*"; else "$@"; fi
}

if [ "$DRY_RUN" -eq 0 ] && [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (or use --dry-run / --destdir)" >&2
    exit 1
fi

STATE="$DESTDIR/var/lib/geoblock"
MANIFEST="$STATE/manifest"
CONF="$DESTDIR$SYSCONFDIR/geoblock/geoblock.conf"

# 1. Remove the firewall table and disable project units (only our own).
if [ -z "$DESTDIR" ]; then
    if command -v geoblock >/dev/null; then
        if [ "$DRY_RUN" -eq 1 ]; then
            geoblock uninstall --dry-run || true
        else
            geoblock uninstall || echo "warning: 'geoblock uninstall' failed; continuing" >&2
        fi
    else
        say "geoblock command not found; skipping firewall/unit teardown"
    fi
fi

# 2. Remove files recorded by the installer.
if [ -f "$MANIFEST" ]; then
    while IFS= read -r path; do
        case $path in /*) ;; *) continue ;; esac
        if [ -e "$DESTDIR$path" ] || [ -L "$DESTDIR$path" ]; then
            run rm -f -- "$DESTDIR$path"
        fi
    done < "$MANIFEST"
    run rm -rf -- "$DESTDIR$PREFIX/lib/geoblock/geoblock/__pycache__"
    run rmdir --ignore-fail-on-non-empty "$DESTDIR$PREFIX/lib/geoblock/geoblock" \
        "$DESTDIR$PREFIX/lib/geoblock" "$DESTDIR$PREFIX/share/doc/geoblock/docs" \
        "$DESTDIR$PREFIX/share/doc/geoblock" "$DESTDIR$PREFIX/share/licenses/geoblock" 2>/dev/null || true
    run rm -f -- "$MANIFEST"
else
    say "no manifest at $MANIFEST; no files removed (installed by a package manager? use it to uninstall)"
fi

# 3. Configuration: kept unless explicitly purged; a modified file is never deleted silently.
if [ -f "$CONF" ]; then
    if [ "$PURGE_CONFIG" -eq 1 ]; then
        run rm -rf -- "$DESTDIR$SYSCONFDIR/geoblock"
    else
        say "kept $CONF (use --purge-config to remove)"
    fi
fi

# 4. State.
if [ "$PURGE_STATE" -eq 1 ]; then
    run rm -rf -- "$STATE"
elif [ -d "$STATE" ]; then
    say "kept $STATE (use --purge-state to remove)"
fi

if [ -z "$DESTDIR" ] && [ "$DRY_RUN" -eq 0 ] && command -v systemctl >/dev/null; then
    systemctl daemon-reload || true
fi
say "done."
