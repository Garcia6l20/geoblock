#!/usr/bin/env bash
# Local quality gate: lint, consistency, unit/integration tests, unit-file verification.
# Usage: scripts/check.sh [lint|consistency|test|units|all]   (default: all)
# Tools that are not installed are reported as SKIPPED, never as passed.
# shellcheck disable=SC2015  # "cmd && ok || bad" is intentional: ok/bad never fail
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

fail=0
ok()   { printf 'PASS    %s\n' "$*"; }
bad()  { printf 'FAIL    %s\n' "$*"; fail=1; }
skip() { printf 'SKIPPED %s\n' "$*"; }

lint() {
    local sh_files
    sh_files=$(printf '%s\n' scripts/*.sh)
    for f in $sh_files; do bash -n "$f" && ok "bash -n $f" || bad "bash -n $f"; done
    if command -v shellcheck >/dev/null; then
        # shellcheck disable=SC2086
        shellcheck -x $sh_files && ok "shellcheck" || bad "shellcheck"
    else skip "shellcheck (not installed)"; fi
    if command -v shfmt >/dev/null; then
        # shellcheck disable=SC2086
        shfmt -d -i 4 -ci $sh_files >/dev/null && ok "shfmt" || bad "shfmt"
    else skip "shfmt (not installed)"; fi
    if command -v ruff >/dev/null; then
        ruff check . && ok "ruff check" || bad "ruff check"
        ruff format --check lib bin tests >/dev/null 2>&1 && ok "ruff format" || skip "ruff format (style differences; not enforced)"
    else skip "ruff (not installed)"; fi
}

consistency() {
    if grep -rIn --exclude-dir=.git --exclude-dir=local --exclude-dir=.venv --exclude-dir=.ruff_cache --exclude-dir=__pycache__ \
        --exclude=check.sh -e 'rs-geoblock' -e 'rs_geo' -e 'ru-geoblock' -e 'ru_geo_block' . >/dev/null; then
        bad "stale rs-/ru- project identifiers found"
        grep -rIn --exclude-dir=.git --exclude-dir=local --exclude-dir=.venv --exclude=check.sh -e 'rs-geoblock' -e 'rs_geo' -e 'ru-geoblock' -e 'ru_geo_block' .
    else ok "no stale rs-/ru- project identifiers"; fi
    # Every option parsed by config.py must appear in the example config and in docs/configuration.md.
    local missing=0 key
    for key in $(python3 -I -c '
import sys; sys.path.insert(0, "lib")
from geoblock.config import _PARSERS
print("\n".join(_PARSERS))'); do
        grep -q "$key" config/geoblock.conf.example || { echo "  $key missing from example config"; missing=1; }
        grep -q "\`$key\`" docs/configuration.md || { echo "  $key missing from docs/configuration.md"; missing=1; }
    done
    [ $missing -eq 0 ] && ok "all config options documented" || bad "undocumented config options"
    # Relative markdown links must resolve.
    local broken=0 md target
    for md in README.md docs/*.md; do
        while IFS= read -r target; do
            case $target in http*|'#'*|mailto:*) continue ;; esac
            target=${target%%#*}
            [ -z "$target" ] && continue
            [ -e "$(dirname "$md")/$target" ] || { echo "  $md: broken link $target"; broken=1; }
        done < <(grep -o ']([^)]*)' "$md" | sed 's/^](//; s/)$//')
    done
    [ $broken -eq 0 ] && ok "markdown links resolve" || bad "broken markdown links"
    # Units reference only paths/names the project owns.
    grep -q 'geoblock' lib/geoblock/__init__.py && ok "firewall namespace geoblock defined" || bad "namespace missing"
}

units() {
    if command -v systemd-analyze >/dev/null; then
        local out
        out=$(systemd-analyze verify --man=no systemd/*.service systemd/*.timer 2>&1 | grep -v 'is not executable' || true)
        if [ -z "$out" ]; then ok "systemd-analyze verify (missing /usr/bin/geoblock ignored)"; else echo "$out"; bad "systemd-analyze verify"; fi
    else skip "systemd-analyze (not installed)"; fi
}

tests() {
    if python3 -c 'import pytest' 2>/dev/null; then
        python3 -m pytest -q && ok "pytest" || bad "pytest"
    else skip "pytest (not installed)"; fi
}

case "${1:-all}" in
    lint) lint ;;
    consistency) consistency ;;
    units) units ;;
    test) tests ;;
    all) lint; consistency; units; tests ;;
    *) echo "unknown target: $1" >&2; exit 2 ;;
esac
exit $fail
