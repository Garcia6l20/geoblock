"""geoblock: block traffic to and from the IP allocations of configured countries with nftables."""

__version__ = "0.1.0"

PROG = "geoblock"
NFT_FAMILY = "inet"
NFT_TABLE = "geoblock"
UNIT_BOOT = "geoblock.service"
UNIT_UPDATE = "geoblock-update.service"
UNIT_APPLY = "geoblock-apply.service"
UNIT_TIMER = "geoblock-update.timer"

DEFAULT_CONFIG = "/etc/geoblock/geoblock.conf"
DEFAULT_STATE_DIR = "/var/lib/geoblock"
