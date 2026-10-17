"""Runs the namespace scenario. Skipped when unprivileged user namespaces are unavailable."""

import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def _userns_ok() -> bool:
    if not (shutil.which("unshare") and shutil.which("nft") and shutil.which("ip") and shutil.which("nsenter")):
        return False
    p = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "nft", "add", "table", "inet", "t"],
                       capture_output=True)
    return p.returncode == 0


@pytest.mark.skipif(not _userns_ok(), reason="needs unprivileged user+net namespaces, nft, iproute2")
def test_namespace_scenario():
    p = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--mount", sys.executable, "-I",
                        os.path.join(HERE, "scenario.py")], capture_output=True, text=True, timeout=600)
    print(p.stdout)
    print(p.stderr)
    assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-3000:]
