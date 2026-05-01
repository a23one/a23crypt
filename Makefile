SHELL := /bin/bash

.PHONY: help test build check release release-test clean

help:
	@printf "Targets:\n"
	@printf "  make test          Run tests with 100%% coverage gate\n"
	@printf "  make build         Build wheel + sdist into dist/\n"
	@printf "  make check         Run tests + build (the full CI gate)\n"
	@printf "  make release       Run check, then publish to PyPI\n"
	@printf "  make release-test  Run check, then publish to TestPyPI\n"
	@printf "  make clean         Remove dist/ and caches\n"

test:
	uv run pytest --cov=a23crypt --cov-report=term --cov-fail-under=100 -q

build:
	rm -rf dist/
	uv build

check: test build
	@printf "\n\033[32m✓ tests pass, coverage 100%%, build clean\033[0m\n"

release: check
	@printf "\n\033[1mPublishing a23crypt 0.1.0 to PyPI\033[0m\n"
	@printf "Artifacts:\n"
	@ls -1 dist/
	@printf "\n"
	@read -p "Proceed with publish to https://pypi.org? [y/N] " confirm; \
	if [ "$$confirm" != "y" ]; then echo "Aborted."; exit 1; fi; \
	if [ -n "$$UV_PUBLISH_TOKEN" ]; then \
		uv publish; \
	else \
		printf "\nGet token from https://pypi.org/manage/account/token/\n"; \
		read -s -p "PyPI API token: " token; \
		printf "\n"; \
		UV_PUBLISH_TOKEN="$$token" uv publish; \
	fi
	@printf "\n\033[32m✓ Published. Verify at https://pypi.org/project/a23crypt/\033[0m\n"

release-test: check
	@printf "\n\033[1mPublishing a23crypt 0.1.0 to TestPyPI\033[0m\n"
	@printf "Artifacts:\n"
	@ls -1 dist/
	@printf "\n"
	@read -p "Proceed with publish to https://test.pypi.org? [y/N] " confirm; \
	if [ "$$confirm" != "y" ]; then echo "Aborted."; exit 1; fi; \
	if [ -n "$$UV_PUBLISH_TOKEN" ]; then \
		uv publish --publish-url https://test.pypi.org/legacy/; \
	else \
		printf "\nGet token from https://test.pypi.org/manage/account/token/\n"; \
		read -s -p "TestPyPI API token: " token; \
		printf "\n"; \
		UV_PUBLISH_TOKEN="$$token" uv publish --publish-url https://test.pypi.org/legacy/; \
	fi
	@printf "\n\033[32m✓ Published. Verify at https://test.pypi.org/project/a23crypt/\033[0m\n"

clean:
	rm -rf dist/ build/ *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
