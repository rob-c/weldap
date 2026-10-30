# Discoverable entry points over the existing scripts. `make` (or `make help`) lists them. Everything here runs
# on a Mac or Linux host; the Windows-only build and the end-to-end acceptance run live in the VMs (see README).
.DEFAULT_GOAL := help
.PHONY: help quality fast lint protocol client server deny imports publish server-image testdir-up testdir-down clean

help: ## List the available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

quality: ## Run every host quality gate (what you should pass before a PR)
	tests/quality.sh

fast: ## Quick gates only: paranoia, budget, protocol (no build, no Docker)
	tests/quality.sh --fast

lint: ## Lint gates: paranoia, code-size budget, protocol consistency, shellcheck
	tests/quality.sh paranoia budget protocol shellcheck

protocol: ## Check the pipe/seal constants agree across C++, C# and Rust
	python3 -I tests/surface/protocol-consistency.py

client: ## C# gate: build (warnings=errors), format, tests, Weldap.Core 100/100 coverage
	tests/quality.sh client

server: ## Rust gate: unsafe confinement, fmt, clippy pedantic, tests, 100/100 coverage (Docker)
	tests/quality.sh server

deny: ## cargo-deny: advisories, licences, bans, sources of the server's dependencies (Docker)
	tests/quality.sh deny

imports: ## Check the credential-provider DLL links no networking library (needs out/provider-*)
	tests/quality.sh imports

publish: ## Build + test the C# service and publish it for win-x64 and win-arm64 into out/
	./build.sh

server-image: ## Build the server's runtime Docker image
	docker build -t weldap-server server/

testdir-up: ## Bring up the local 389 DS + WELDAP server test directory
	testdir/up.sh

testdir-down: ## Stop the local test directory
	cd testdir && docker compose down

clean: ## Remove build output (out/, bin/, obj/)
	rm -rf out
	find . -type d \( -name bin -o -name obj \) -not -path './vm/*' -prune -exec rm -rf {} +
