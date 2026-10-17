import json
import os
import subprocess
import sys

import pytest

import helpers

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI = [sys.executable, "-I", os.path.join(ROOT, "bin", "geoblock")]


def run(tmp, cfg, *args):
    return subprocess.run([*CLI, "--config", cfg, "--state-dir", os.path.join(tmp, "state"), "--no-systemd", *args],
                          capture_output=True, text=True, env={"PATH": os.environ["PATH"], "GEOBLOCK_TESTING": "1"})


def test_check_config_ok_and_bad(tmp):
    good = helpers.write_config(tmp)
    assert run(tmp, good, "check-config").returncode == 0
    with open(good, "a") as fh:
        fh.write("surprise = 1\n")
    p = run(tmp, good, "check-config")
    assert p.returncode == 2 and "unknown option" in p.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="needs an unprivileged user")
@pytest.mark.parametrize("cmd", [["enable"], ["disable"], ["update"], ["rollback"], ["install"], ["uninstall"]])
def test_mutating_commands_require_root(tmp, cmd):
    p = run(tmp, helpers.write_config(tmp), *cmd)
    assert p.returncode == 4 and "root" in p.stderr


def test_status_without_installation(tmp):
    p = run(tmp, helpers.write_config(tmp), "status", "--json")
    assert p.returncode == 0
    data = json.loads(p.stdout)
    assert data["enabled"] is False and "dataset" not in data


def test_status_text_distinguishes_states(tmp):
    p = run(tmp, helpers.write_config(tmp), "status")
    assert "installed" in p.stdout and "enabled" in p.stdout and "active" in p.stdout


def test_list_without_data_is_not_ready(tmp):
    p = run(tmp, helpers.write_config(tmp), "list")
    assert p.returncode == 6


def test_rollback_dry_run_without_history(tmp):
    p = run(tmp, helpers.write_config(tmp), "rollback", "--dry-run")
    assert p.returncode == 6 and "nothing to roll back" in p.stderr


def test_update_dry_run_changes_nothing(tmp, server):
    cfg = helpers.write_config(tmp, server)
    p = run(tmp, cfg, "update", "--dry-run")
    assert p.returncode == 0, p.stderr
    assert not os.path.exists(os.path.join(tmp, "state"))


def test_update_dry_run_rejects_bad_data(tmp, server):
    server.routes["/xx-v4.zone"] = (200, "nonsense\n")
    p = run(tmp, helpers.write_config(tmp, server), "update", "--dry-run")
    assert p.returncode == 5


def test_unknown_command(tmp):
    assert run(tmp, helpers.write_config(tmp), "frobnicate").returncode == 2
