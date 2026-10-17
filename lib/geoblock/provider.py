"""Country-list providers. A provider maps an address family to a source URL.

Adding a provider means adding an entry to PROVIDERS; the firewall engine only
consumes validated Dataset objects and never learns where they came from.
"""

from dataclasses import dataclass

from .config import Settings
from .errors import ConfigError


@dataclass(frozen=True)
class Provider:
    name: str
    ipv4_url: str
    ipv6_url: str
    terms_url: str

    def url(self, family: int, country: str) -> str:
        template = self.ipv4_url if family == 4 else self.ipv6_url
        return template.replace("{cc}", country)


PROVIDERS = {
    "ipdeny": Provider(
        name="ipdeny",
        ipv4_url="https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone",
        ipv6_url="https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone",
        terms_url="https://www.ipdeny.com/usagelimits.php",
    ),
}


def resolve(settings: Settings) -> Provider:
    base = PROVIDERS.get(settings.provider)
    if base is None:
        raise ConfigError(f"unknown provider '{settings.provider}'")
    return Provider(
        name=base.name,
        ipv4_url=settings.ipv4_url or base.ipv4_url,
        ipv6_url=settings.ipv6_url or base.ipv6_url,
        terms_url=base.terms_url,
    )
