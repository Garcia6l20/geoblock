# geoblock - installation and development targets.
#   make install [PREFIX=/usr/local] [DESTDIR=...]   install files (never touches the firewall)
#   make list-installed                        print every path `install` creates
#   make check                                 lint + tests (no root, no host firewall changes)
#   make dist                                  source tarball for packaging

PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc
LIBDIR     ?= $(PREFIX)/lib/geoblock
UNITDIR    ?= $(PREFIX)/lib/systemd/system
VERSION    := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' lib/geoblock/__init__.py)

PY_FILES   := $(notdir $(wildcard lib/geoblock/*.py))
UNITS      := geoblock.service geoblock-update.service geoblock-apply.service geoblock-update.timer
DOCS       := README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md $(addprefix docs/,$(notdir $(wildcard docs/*.md)))

INSTALLED  := $(PREFIX)/bin/geoblock \
              $(addprefix $(LIBDIR)/geoblock/,$(PY_FILES)) \
              $(addprefix $(UNITDIR)/,$(UNITS)) \
              $(PREFIX)/lib/sysusers.d/geoblock.conf \
              $(PREFIX)/lib/tmpfiles.d/geoblock.conf \
              $(PREFIX)/share/doc/geoblock/geoblock.conf.example \
              $(addprefix $(PREFIX)/share/doc/geoblock/,$(DOCS)) \
              $(PREFIX)/share/licenses/geoblock/LICENSE

.PHONY: install install-config list-installed check lint test dist clean

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	sed 's|^LIBDIR = ".*"|LIBDIR = "$(LIBDIR)"|' bin/geoblock > $(DESTDIR)$(PREFIX)/bin/geoblock
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/geoblock
	for f in $(PY_FILES); do install -Dm644 lib/geoblock/$$f $(DESTDIR)$(LIBDIR)/geoblock/$$f; done
	for u in $(UNITS); do sed 's|/usr/bin/geoblock|$(PREFIX)/bin/geoblock|g' systemd/$$u > $$u.tmp && install -Dm644 $$u.tmp $(DESTDIR)$(UNITDIR)/$$u; rm -f $$u.tmp; done
	install -Dm644 systemd/geoblock.sysusers $(DESTDIR)$(PREFIX)/lib/sysusers.d/geoblock.conf
	install -Dm644 systemd/geoblock.tmpfiles $(DESTDIR)$(PREFIX)/lib/tmpfiles.d/geoblock.conf
	install -Dm644 config/geoblock.conf.example $(DESTDIR)$(PREFIX)/share/doc/geoblock/geoblock.conf.example
	for d in $(DOCS); do install -Dm644 $$d $(DESTDIR)$(PREFIX)/share/doc/geoblock/$$d; done
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/geoblock/LICENSE

# Create the active configuration only if the administrator has none yet.
install-config:
	@if [ -e $(DESTDIR)$(SYSCONFDIR)/geoblock/geoblock.conf ]; then \
	  echo "keeping existing $(SYSCONFDIR)/geoblock/geoblock.conf"; \
	else install -Dm644 config/geoblock.conf.example $(DESTDIR)$(SYSCONFDIR)/geoblock/geoblock.conf; fi

list-installed:
	@printf '%s\n' $(INSTALLED)

lint:
	./scripts/check.sh lint

test:
	python3 -m pytest -q

check:
	./scripts/check.sh

dist:
	rm -rf dist && mkdir -p dist/geoblock-$(VERSION)
	cp -r README.md LICENSE CHANGELOG.md SECURITY.md CONTRIBUTING.md Makefile pyproject.toml bin lib config \
	    systemd scripts docs tests packaging .github dist/geoblock-$(VERSION)/
	find dist -name __pycache__ -prune -exec rm -rf {} +
	tar -C dist -czf dist/geoblock-$(VERSION).tar.gz geoblock-$(VERSION)
	@echo dist/geoblock-$(VERSION).tar.gz

clean:
	rm -rf dist .pytest_cache .ruff_cache
	find . -name __pycache__ -prune -exec rm -rf {} +
