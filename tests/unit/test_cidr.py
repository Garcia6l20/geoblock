import pytest

from geoblock import cidr
from geoblock.errors import DataError


def test_valid_ipv4_and_ipv6():
    d4 = cidr.parse_zone("203.0.113.0/24\n198.51.100.0/25\n", 4)
    assert d4.count == 2
    d6 = cidr.parse_zone("2001:0db8:0000:0000:0000:0000:0000:0000/32\n", 6)
    assert str(d6.networks[0]) == "2001:db8::/32"


@pytest.mark.parametrize("line", [
    "203.0.113.1/24",          # host bits set
    "203.0.113.0",             # no prefix
    "203.0.113.0/33",
    "203.0.113.0/255.255.255.0",
    "203.0.113.256/24",
    "203.0.113.0/24 # c",
    " 203.0.113.0/24",
    "203.0.113.0/24\r",
    "0203.0.113.0/24",
    "example.com/24",
    "$(touch x)/24",
    "203.0.113.0/-1",
])
def test_invalid_ipv4_rejected(line):
    with pytest.raises(DataError):
        cidr.parse_zone(line + "\n", 4)


def test_wrong_family_rejected():
    with pytest.raises(DataError):
        cidr.parse_zone("2001:db8::/32\n", 4)
    with pytest.raises(DataError):
        cidr.parse_zone("203.0.113.0/24\n", 6)


def test_ipv6_invalid():
    for line in ("2001:db8::1/32", "2001:db8::/129", "2001:db8::%eth0/32", "gggg::/32"):
        with pytest.raises(DataError):
            cidr.parse_zone(line + "\n", 6)


def test_comments_and_blank_lines_ignored():
    assert cidr.parse_zone("# header\n\n203.0.113.0/24\n", 4).count == 1


def test_duplicates_counted_and_removed():
    d = cidr.parse_zone("203.0.113.0/24\n203.0.113.0/24\n", 4)
    assert d.count == 1 and d.duplicates == 1


def test_overlap_collapsed():
    d = cidr.parse_zone("203.0.113.0/24\n203.0.113.0/25\n203.0.113.128/25\n", 4)
    assert d.count == 3 and [str(n) for n in d.collapsed] == ["203.0.113.0/24"]


def test_empty_and_undersized():
    with pytest.raises(DataError, match="below"):
        cidr.validate_dataset("", 4, 1)
    with pytest.raises(DataError, match="below"):
        cidr.validate_dataset("203.0.113.0/24\n", 4, 2)
    assert cidr.validate_dataset("203.0.113.0/24\n", 4, 1).count == 1


def test_html_error_page_rejected():
    with pytest.raises(DataError):
        cidr.parse_zone("<html><body>503</body></html>\n", 4)


@pytest.mark.parametrize("line", ["0.0.0.0/0", "127.0.0.0/8", "127.0.0.1/32", "10.1.0.0/16", "192.168.1.0/24",
                                  "169.254.0.0/16", "224.0.0.0/4", "100.64.0.0/10", "0.0.0.0/4"])
def test_protected_ipv4_rejected(line):
    with pytest.raises(DataError):
        cidr.parse_zone(line + "\n", 4)


@pytest.mark.parametrize("line", ["::/0", "::1/128", "fe80::/10", "fd00::/8", "ff00::/8", "::ffff:0:0/96", "2000::/3"])
def test_protected_or_huge_ipv6_rejected(line):
    with pytest.raises(DataError):
        cidr.parse_zone(line + "\n", 6)


def test_shrink_check():
    cidr.check_shrink(60, 100, 50, 4)
    with pytest.raises(DataError, match="shrank"):
        cidr.check_shrink(49, 100, 50, 4)
    cidr.check_shrink(1, 100, 100, 4)


def test_too_many_lines():
    with pytest.raises(DataError, match="too many"):
        cidr.parse_zone("\n" * (cidr.MAX_LINES + 1), 4)


def test_ranges_merge_adjacent():
    nets = cidr.parse_zone("203.0.113.0/25\n203.0.113.128/25\n198.51.100.0/24\n", 4).networks
    assert len(cidr.to_ranges(nets)) == 2
