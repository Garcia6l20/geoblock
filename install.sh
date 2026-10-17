#!/usr/bin/env bash
# One-line installer:
#   curl -fsSL https://raw.githubusercontent.com/Garcia6l20/geoblock/refs/heads/main/install.sh | bash
# Pass options after "-s --", e.g.:  ... | bash -s -- --dry-run
#
# Downloads the repository tarball over HTTPS, then runs scripts/install.sh from it. It installs
# files and systemd units only and never enables the firewall policy.
# Environment: GEOBLOCK_REF (branch or tag, default "main"), GEOBLOCK_TARBALL_URL (full override).
set -euo pipefail

main() {
    local repo="Garcia6l20/geoblock"
    local ref="${GEOBLOCK_REF:-main}"
    local url="${GEOBLOCK_TARBALL_URL:-https://github.com/${repo}/archive/${ref}.tar.gz}"

    for tool in curl tar make python3; do
        command -v "$tool" >/dev/null || { echo "error: '$tool' is required (on Arch: pacman -S curl tar make python)" >&2; exit 1; }
    done

    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT

    echo "Downloading ${url}"
    curl -fsSL --proto '=https,file' --max-time 120 -o "$tmp/src.tar.gz" "$url"
    mkdir "$tmp/src"
    tar -xzf "$tmp/src.tar.gz" -C "$tmp/src" --strip-components=1
    [ -x "$tmp/src/scripts/install.sh" ] || { echo "error: unexpected archive layout" >&2; exit 1; }

    local runner=()
    if [ "$(id -u)" -ne 0 ] && [[ " $* " != *" --dry-run "* ]] && [[ " $* " != *" --destdir "* ]]; then
        command -v sudo >/dev/null || { echo "error: run as root or install sudo" >&2; exit 1; }
        runner=(sudo)
    fi
    "${runner[@]}" "$tmp/src/scripts/install.sh" "$@"
}

main "$@"
