PYTHON=python3
CHANGELOG=CHANGELOG.md
GEN_SCRIPT=scripts/generate_changelog_section.py

.PHONY: release
release:
	@echo "Creating release draft (local)"
	@if [ -z "$(TAG)" ]; then echo "Usage: make release TAG=v0.1.0"; exit 1; fi
	@tmpfile=$$(mktemp); \
	$(PYTHON) $(GEN_SCRIPT) --section "Unreleased" > $$tmpfile; \
	gh release create $(TAG) --draft -F $$tmpfile --title "$(TAG)"; \
	rm -f $$tmpfile; \
	@echo "Draft release created for $(TAG)";
