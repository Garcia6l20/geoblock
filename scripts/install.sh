#!/usr/bin/env bash
# Install geoblock from a source checkout. Safe to run repeatedly.
# This installs files and systemd units only; it never changes firewall rules.
# Activate the policy afterwards with: sudo geoblock enable
set -euo pipefail

PREFIX=/usr/local
DESTDIR=
DRY_RUN=0
SYSTEM_SETUP=1
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
    cat <<USAGE
Usage: $0 [--dry-run] [--prefix DIR] [--destdir DIR] [--no-system-setup]
  --dry-run          show what would be done, change nothing
  --prefix DIR       installation prefix (default: /usr/local)
  --destdir DIR      staging root (implies --no-system-setup)
  --no-system-setup  do not run systemd-sysusers/tmpfiles/daemon-reload
USAGE
}

while [ $# -gt 0 ]; do
    case $1 in
        --dry-run) DRY_RUN=1 ;;
        --prefix) PREFIX=${2:?--prefix needs a value}; shift ;;
        --destdir) DESTDIR=${2:?--destdir needs a value}; SYSTEM_SETUP=0; shift ;;
        --no-system-setup) SYSTEM_SETUP=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say() { printf '%s\n' "$*"; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then say "[dry-run] $*"; else "$@"; fi
}
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- prerequisites ---------------------------------------------------------------
if [ "$DRY_RUN" -eq 0 ] && [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    die "must run as root (or use --dry-run / --destdir)"
fi

# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
case " ${ID:-} ${ID_LIKE:-} " in
    *" arch "*|*" cachyos "*|*" manjaro "*) say "detected: ${PRETTY_NAME:-$ID}" ;;
    *) warn "${PRETTY_NAME:-unknown OS} is not Arch-based; this is untested" ;;
esac

command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "python 3.11 or newer is required"
command -v nft >/dev/null || die "nft not found; install the 'nftables' package first"
command -v make >/dev/null || die "make is required"

if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet firewalld.service 2>/dev/null; then
        die "firewalld is active; coexistence with geoblock is not verified"
    fi
    if systemctl is-active --quiet ufw.service 2>/dev/null; then
        say "detected: UFW active (left untouched)"
    else
        say "note: UFW is not active; geoblock works independently of it"
    fi
fi
say "iptables backend: $(iptables --version 2>/dev/null || echo 'not installed')"

# --- record ownership first so an interrupted install can still be removed -------
MANIFEST_DIR="$DESTDIR/var/lib/geoblock"
FILES=$(make -s -C "$SRC" list-installed PREFIX="$PREFIX")
run install -d -m 0755 "$MANIFEST_DIR"
if [ "$DRY_RUN" -eq 1 ]; then
    say "[dry-run] would record $(printf '%s\n' "$FILES" | wc -l) paths in $MANIFEST_DIR/manifest"
else
    printf '%s\n' "$FILES" > "$MANIFEST_DIR/manifest.tmp"
    mv -f "$MANIFEST_DIR/manifest.tmp" "$MANIFEST_DIR/manifest"
fi

# --- files ----------------------------------------------------------------------
run make -s -C "$SRC" install PREFIX="$PREFIX" DESTDIR="$DESTDIR"
run make -s -C "$SRC" install-config PREFIX="$PREFIX" DESTDIR="$DESTDIR"

if [ "$SYSTEM_SETUP" -eq 1 ]; then
    run systemd-sysusers "$DESTDIR$PREFIX/lib/sysusers.d/geoblock.conf"
    run systemd-tmpfiles --create "$DESTDIR$PREFIX/lib/tmpfiles.d/geoblock.conf"
    run systemctl daemon-reload
fi

say
say "Installed. The firewall policy is NOT active."
say "Next steps:"
say "  sudo geoblock test       # read-only checks"
say "  sudo geoblock install    # download and validate the first dataset"
say "  sudo geoblock enable     # load the rules and enable boot + daily updates"
