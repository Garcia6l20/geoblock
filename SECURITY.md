# Security policy

Report vulnerabilities privately to Garcia Sylvain <garcia.g6l20@gmail.com>, or through GitHub
private vulnerability reporting on <https://github.com/G6L20/geoblock>. Please do not open public issues
for exploitable problems. Expect an acknowledgement within a few days.

Security-relevant design is described in `docs/threat-model.md` and `docs/design.md`. In scope:
privilege separation, parsing of untrusted data, file handling in `/var/lib/geoblock`, firewall
coexistence. Out of scope: bypasses by VPNs/proxies (documented limitation).
