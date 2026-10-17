import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.insert(0, os.path.dirname(__file__))

import helpers  # noqa: E402


@pytest.fixture
def tmp():
    d = helpers.tmpdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def server(tmp):
    s = helpers.Server(tmp)
    s.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST))
    s.routes["/xx-v6.zone"] = (200, helpers.zone(helpers.V6_TEST))
    yield s
    s.close()
