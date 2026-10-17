import os

import pytest

from geoblock import config
from geoblock.errors import ConfigError


def test_defaults():
    s = config.parse_text("")
    assert s.ipv4 and s.ipv6 and s.block_input and s.block_output and not s.block_forward
    assert s.output_action == "reject"


def test_parse_values_and_comments():
    s = config.parse_text("# c\nipv6 = no   # trailing\noutput_action = drop\nallow_ipv4 = 203.0.113.0/24, 198.51.100.1/32\n")
    assert not s.ipv6 and s.output_action == "drop" and len(s.allow_ipv4) == 2


@pytest.mark.parametrize("text", [
    "bogus = 1", "ipv4 = maybe", "ipv4 yes", "retries = 99", "retries = x", "output_action = accept",
    "ipv4_url = http://example.com/x", "ipv4_url = https://user:pw@example.com/x", "allow_ipv4 = 10.0.0.1",
    "allow_ipv4 = 2001:db8::/32", "allow_ipv6 = 203.0.113.0/24", "log_level = loud", "service_user = Root!",
    "ipv4 = yes\nipv4 = no", "ipv4 = no\nipv6 = no", "block_input = no\nblock_output = no\nblock_forward = no",
    "ca_file = relative/path", "hook_priority = 5000", "min_entries_v4 = 0", "nft_command = /bin/sh",
    "ipv4 = yes\x00", "ipv4 = yes; rm -rf /",
])
def test_invalid_rejected(text):
    with pytest.raises(ConfigError):
        config.parse_text(text)


def test_load_missing_gives_defaults(tmp):
    assert config.load(os.path.join(tmp, "none.conf")) == config.Settings()


def test_load_rejects_writable_and_symlink(tmp):
    p = os.path.join(tmp, "c.conf")
    open(p, "w").write("ipv4 = yes\n")
    os.chmod(p, 0o666)
    with pytest.raises(ConfigError, match="writable"):
        config.load(p)
    os.chmod(p, 0o644)
    link = os.path.join(tmp, "l.conf")
    os.symlink(p, link)
    with pytest.raises(ConfigError):
        config.load(link)


def test_load_size_limit(tmp):
    p = os.path.join(tmp, "big.conf")
    open(p, "w").write("# x\n" * 40000)
    with pytest.raises(ConfigError, match="too large"):
        config.load(p)


def test_example_config_is_valid():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    config.load(os.path.join(root, "config", "geoblock.conf.example"))


def test_countries_parsing_and_validation():
    assert config.parse_text("countries = RU, nl").countries == ("ru", "nl")
    for bad in ("countries = russia", "countries = ru, ru", "countries = r1", "countries = " + ",".join(["aa"] * 25)):
        with pytest.raises(ConfigError):
            config.parse_text(bad)


def test_no_default_country():
    assert config.parse_text("").countries == ()
