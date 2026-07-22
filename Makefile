# aauth-core — developer tasks
#
# Run `make` (or `make help`) to list targets. `make ci` mirrors what the
# GitHub Actions PR workflow runs.

CARGO ?= cargo
MSRV  ?= 1.86

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the library (all features)
	$(CARGO) build --all-features

.PHONY: test
test: ## Run all tests (all features)
	$(CARGO) test --all-features

.PHONY: fmt
fmt: ## Format the code in place
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying files
	$(CARGO) fmt --all --check

.PHONY: clippy
clippy: ## Lint with clippy, warnings as errors
	$(CARGO) clippy --all-targets --all-features -- -D warnings

.PHONY: examples
examples: ## Compile (and thus check) the README examples in examples/
	$(CARGO) build --examples --all-features

.PHONY: doc
doc: ## Build docs, warnings as errors
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --all-features

.PHONY: audit
audit: ## Check dependencies for known vulnerabilities (needs cargo-audit)
	$(CARGO) audit

.PHONY: msrv
msrv: ## Verify the crate builds on the declared MSRV (needs rustup + toolchain $(MSRV))
	rustup toolchain install $(MSRV) --profile minimal 2>/dev/null || true
	$(CARGO) +$(MSRV) check --all-features

.PHONY: ci
ci: fmt-check clippy test examples doc ## Run the full PR gate locally

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
