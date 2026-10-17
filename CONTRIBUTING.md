# Contributing

1. Run `./scripts/check.sh` and `python3 -m pytest -q` before sending changes; see `docs/development.md`.
2. Keep dependencies at zero beyond the Python standard library; no `eval`, no shell string building.
3. Anything that touches firewall state needs a test (fake-`nft` unit test and, if behaviour on the wire
   changes, the namespace scenario). Never claim a test passed that was not run.
4. Never flush rulesets or touch tables other than `inet geoblock`.
5. Document new options in `config/geoblock.conf.example` and `docs/configuration.md` (CI checks this).
