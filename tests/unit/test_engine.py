"""Engine tests with a fake nft: failed updates, rollback, atomic publication, locking."""

import json
import os
import threading

import pytest

import helpers
from geoblock import cidr, config, engine
from geoblock.errors import BusyError, DataError, FirewallError, NotReadyError
from geoblock.nftables import Nft, render_ruleset
from geoblock.state import State


@pytest.fixture
def env(tmp, server):
    cfgpath = helpers.write_config(tmp, server)
    settings = config.load(cfgpath)
    fake = os.path.join(tmp, "fake")
    os.mkdir(fake)
    nft = Nft(binary=helpers.make_fake_nft(fake))
    state = State(os.path.join(tmp, "state"))
    eng = engine.Engine(settings, state, nft, require_root=False)
    return type("Env", (), {"tmp": tmp, "fake": fake, "server": server, "settings": settings,
                            "state": state, "eng": eng, "nft": nft})


def flag(env, name, on=True):
    p = os.path.join(env.fake, name)
    if on:
        open(p, "w").close()
    elif os.path.exists(p):
        os.unlink(p)


def full_update(env, activate=False):
    engine.fetch_stage(env.settings, env.state)
    return env.eng.apply_stage(activate=activate, use_staged=True)


def test_update_publishes_generation_without_loading(env):
    res = full_update(env)
    assert res.changed and not res.activated
    cur = env.state.current()
    assert cur.meta["ipv4"]["count"] == len(helpers.V4_TEST)
    assert not os.path.exists(os.path.join(env.fake, "last-loaded"))  # not enabled -> nothing loaded
    assert env.state.is_enabled() is False


def test_enable_loads_ruleset_and_sets_flag(env):
    full_update(env)
    flag(env, "dummy", False)
    # Fake nft returns no listing, so verification must fail and nothing may be marked enabled.
    with pytest.raises(FirewallError):
        env.eng.apply_stage(activate=True, use_staged=False)
    assert env.state.is_enabled() is False


def _fake_listing(env, gen):
    """Make the fake nft report exactly what `gen` would install."""
    from geoblock.nftables import render_ruleset  # noqa: F401
    sets = {}
    for fam in (4, 6):
        nets = cidr.parse_zone(gen.read(f"ipv{fam}.txt"), fam).collapsed
        sets[f"blocked_v{fam}"] = [{"prefix": {"addr": str(n.network_address), "len": n.prefixlen}} for n in nets]
    items = [{"metainfo": {}}, {"table": {"name": "geoblock"}}]
    for name, elems in sets.items():
        items.append({"set": {"name": name, "elem": elems}})
    for ch in ("input", "output"):
        items.append({"chain": {"name": ch, "hook": ch, "prio": env.settings.hook_priority}})
    with open(os.path.join(env.fake, "listing.json"), "w") as fh:
        json.dump({"nftables": items}, fh)


def test_failed_check_leaves_state_untouched(env):
    full_update(env)
    before = env.state.current().id
    flag(env, "fail-check")
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST + ["203.0.113.200/32"]))
    engine.fetch_stage(env.settings, env.state)
    with pytest.raises(FirewallError):
        env.eng.apply_stage()
    assert env.state.current().id == before
    assert len(env.state.list_ids()) == 1


def test_failed_load_discards_new_generation_and_keeps_old(env):
    full_update(env)
    cur = env.state.current()
    env.state.set_enabled(True)
    _fake_listing(env, cur)
    flag(env, "fail-load")
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST + ["203.0.113.200/32"]))
    engine.fetch_stage(env.settings, env.state)
    with pytest.raises(FirewallError, match="load"):
        env.eng.apply_stage()
    assert env.state.current().id == cur.id
    assert env.state.list_ids() == [cur.id]
    assert json.load(open(env.state.last_update_file))["ok"] is False


def test_verification_failure_restores_previous_ruleset(env):
    full_update(env)
    cur = env.state.current()
    env.state.set_enabled(True)
    # listing describes the OLD data, so verification of the new ruleset must fail
    _fake_listing(env, cur)
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST + ["203.0.113.200/32"]))
    engine.fetch_stage(env.settings, env.state)
    with pytest.raises(FirewallError, match="does not match"):
        env.eng.apply_stage()
    assert env.state.current().id == cur.id
    restored = open(os.path.join(env.fake, "last-loaded")).read()
    assert restored == cur.read("ruleset.nft")  # previous known-good ruleset was loaded back


def test_invalid_upstream_data_never_reaches_staging_or_state(env):
    full_update(env)
    cur = env.state.current().id
    for body in ("garbage\n", "", "127.0.0.0/8\n", helpers.zone(["203.0.113.0/24"]) + "oops\n"):
        env.server.routes["/xx-v4.zone"] = (200, body)
        with pytest.raises(DataError):
            engine.fetch_stage(env.settings, env.state)
    assert env.state.current().id == cur
    staged = engine.read_staged(env.settings, env.state)
    assert staged.texts[("xx", 4)] == helpers.zone(helpers.V4_TEST)  # old staged data intact
    assert json.load(open(os.path.join(env.state.staging, "fetch-status.json")))["ok"] is False


def test_shrink_protection(env):
    big = [f"198.51.{i}.0/24" for i in range(100)]
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(big))
    full_update(env)
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(big[:20]))
    engine.fetch_stage(env.settings, env.state)
    with pytest.raises(DataError, match="shrank"):
        env.eng.apply_stage()


def test_unchanged_dataset_creates_no_new_generation(env):
    full_update(env)
    res = full_update(env)
    assert not res.changed and len(env.state.list_ids()) == 1


def test_rollback_swaps_pointers(env):
    full_update(env)
    first = env.state.current()
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST + ["203.0.113.200/32"]))
    full_update(env)
    second = env.state.current()
    assert second.id != first.id and env.state.previous().id == first.id
    assert "rolled back" in env.eng.rollback()
    assert env.state.current().id == first.id and env.state.previous().id == second.id


def test_rollback_without_previous(env):
    full_update(env)
    with pytest.raises(NotReadyError):
        env.eng.rollback()


def test_rollback_failure_keeps_pointers(env):
    full_update(env)
    env.server.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST + ["203.0.113.200/32"]))
    full_update(env)
    cur, prev = env.state.current().id, env.state.previous().id
    flag(env, "fail-check")
    with pytest.raises(FirewallError):
        env.eng.rollback()
    assert (env.state.current().id, env.state.previous().id) == (cur, prev)


def test_prune_keeps_current_and_previous(env):
    for i in range(5):
        env.server.routes["/xx-v4.zone"] = (200, helpers.zone(helpers.V4_TEST + [f"203.0.113.{200 + i}/32"]))
        full_update(env)
    assert len(env.state.list_ids()) == 5
    env.state.prune(2)
    ids = env.state.list_ids()
    assert len(ids) == 2 and env.state.current().id in ids and env.state.previous().id in ids


def test_generation_publication_is_atomic_symlink(env):
    full_update(env)
    assert os.path.islink(env.state.current_link)
    assert os.readlink(env.state.current_link).startswith("generations/")
    leftovers = [n for n in os.listdir(env.state.dir) if ".tmp-" in n]
    assert leftovers == []


def test_tampered_generation_detected(env):
    full_update(env)
    cur = env.state.current()
    env.state.set_enabled(True)
    with open(os.path.join(cur.path, "ipv4.txt"), "a") as fh:
        fh.write("203.0.113.222/32\n")
    with pytest.raises(DataError, match="integrity"):
        engine._datasets_from_generation(env.settings, cur)
    with open(os.path.join(cur.path, "ruleset.nft"), "a") as fh:
        fh.write("#x\n")
    with pytest.raises(DataError, match="integrity"):
        env.eng.load_stage()


def test_staging_symlink_is_not_followed(env):
    full_update(env)
    secret = os.path.join(env.tmp, "secret")
    open(secret, "w").write("203.0.113.9/32\n")
    target = os.path.join(env.state.staging, "xx-ipv4.zone")
    os.unlink(target)
    os.symlink(secret, target)
    with pytest.raises(DataError):
        engine.read_staged(env.settings, env.state)


def test_staging_tampered_content_detected(env):
    full_update(env)
    with open(os.path.join(env.state.staging, "xx-ipv4.zone"), "a") as fh:
        fh.write("203.0.113.77/32\n")
    with pytest.raises(DataError, match="manifest"):
        engine.read_staged(env.settings, env.state)


def test_staging_without_manifest_is_ignored(env):
    engine.fetch_stage(env.settings, env.state)
    os.unlink(os.path.join(env.state.staging, "fetch.json"))
    assert engine.read_staged(env.settings, env.state) is None


def test_concurrent_invocations_are_serialised(env):
    with env.state.lock(env.state.staging_lock) if os.path.isdir(env.state.staging) else _mk(env):
        with pytest.raises(BusyError):
            env.eng.apply_stage(dry_run=True)


def _mk(env):
    os.makedirs(env.state.staging)
    return env.state.lock(env.state.staging_lock)


def test_lock_released_after_use(env):
    os.makedirs(env.state.dir, exist_ok=True)
    with env.state.lock():
        pass
    with env.state.lock():
        pass


def test_lock_contention_between_threads(env):
    os.makedirs(env.state.dir, exist_ok=True)
    got = []

    def other():
        try:
            with env.state.lock():
                got.append("acquired")
        except BusyError:
            got.append("busy")

    with env.state.lock():
        t = threading.Thread(target=other)
        t.start()
        t.join()
    assert got == ["busy"]


def test_ruleset_is_scoped_to_own_table(env):
    full_update(env)
    text = env.state.current().read("ruleset.nft")
    assert text.startswith("add table inet geoblock\ndelete table inet geoblock\n")
    assert "flush" not in text
    for line in text.splitlines():
        if line.startswith(("add ", "delete ", "table ", "flush ")):
            assert "geoblock" in line


def test_render_variants():
    s = config.parse_text("block_forward = yes\nallow_ipv4 = 203.0.113.1/32\noutput_action = drop\n")
    v4 = cidr.parse_zone("203.0.113.0/24\n", 4).collapsed
    v6 = cidr.parse_zone("2001:db8::/32\n", 6).collapsed
    text = render_ruleset(s, v4, v6)
    assert "chain forward" in text and "set allow_v4" in text and "set allow_v6" not in text
    assert 'ip daddr @blocked_v4 counter drop comment "geoblock-output-v4"' in text
    assert "ct state" not in text
    s2 = config.parse_text("ipv6 = no\nblock_input = no\n")
    t2 = render_ruleset(s2, v4, v6)
    assert "blocked_v6" not in t2 and "chain input" not in t2


def test_ipv6_disabled_only_fetches_ipv4(env):
    from dataclasses import replace
    env.settings = replace(env.settings, ipv6=False)
    env.eng.s = env.settings
    engine.fetch_stage(env.settings, env.state)
    assert "/xx-v6.zone" not in env.server.hits


def test_no_countries_refuses_to_run(env):
    from dataclasses import replace
    s = replace(env.settings, countries=())
    with pytest.raises(Exception, match="no countries"):
        engine.fetch_stage(s, env.state)
    with pytest.raises(Exception, match="no countries"):
        engine.Engine(s, env.state, env.nft, require_root=False).apply_stage()


def test_multiple_countries_are_merged_and_changes_require_update(env):
    from dataclasses import replace
    env.server.routes["/yy-v4.zone"] = (200, helpers.zone(["192.0.2.128/25", "203.0.113.200/32"]))
    env.server.routes["/yy-v6.zone"] = (200, helpers.zone(["2001:db8:3::/48"]))
    s = replace(env.settings, countries=("xx", "yy"))
    eng = engine.Engine(s, env.state, env.nft, require_root=False)
    engine.fetch_stage(s, env.state)
    eng.apply_stage()
    cur = env.state.current()
    assert cur.meta["countries"] == ["xx", "yy"]
    nets = cidr.parse_zone(cur.read("ipv4.txt"), 4).networks
    assert cidr.contains(nets, "203.0.113.200") and cidr.contains(nets, "198.51.100.9")
    # changing the country list without fetching must not silently reuse old data
    eng2 = engine.Engine(replace(s, countries=("xx",)), env.state, env.nft, require_root=False)
    with pytest.raises(NotReadyError):
        eng2.apply_stage(use_staged=False)
    # one country failing validation aborts the whole fetch
    env.server.routes["/yy-v4.zone"] = (200, "junk\n")
    with pytest.raises(DataError, match="YY"):
        engine.fetch_stage(s, env.state)
