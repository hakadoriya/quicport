export SHELL             := /usr/bin/env bash -Eeu -o pipefail
export REPO_ROOT         := $(shell git rev-parse --show-toplevel)
export MAKEFILE_DIR      := $(shell { cd "$(subst /,,$(dir $(lastword ${MAKEFILE_LIST})))" && pwd; } || pwd)
export DOTLOCAL_DIR      := ${MAKEFILE_DIR}/.local
export DOTLOCAL_BIN_DIR  := ${DOTLOCAL_DIR}/bin
export CURRENT_VERSION     := $(shell git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)
export CURRENT_REVISION    := $(shell git rev-parse HEAD)
export CURRENT_BRANCH      := $(shell git rev-parse --abbrev-ref HEAD)
export CURRENT_TIMESTAMP   := $(shell git log -n 1 --format='%cI')

export PATH := ${DOTLOCAL_BIN_DIR}:${REPO_ROOT}/.bin:${PATH}

.DEFAULT_GOAL := help
.PHONY: help
help:  ## Display this help documents
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-40s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup:  ## Setup tools for development
	# == SETUP =====================================================
	# versenv
	make versenv
	# --------------------------------------------------------------

.PHONY: versenv
versenv:
	# direnv
	direnv allow .
	# gitleaks
	gitleaks version
	# typos
	typos --version

.PHONY: generate
generate:  ## Generate code
	# noop

.PHONY: update
update:  ## Update dependencies
	cargo update

.PHONY: build
build:  ## Build binary
	cargo build --offline --release

.PHONY: clean
clean:  ## Clean up cache, etc
	# remove target
	rm -rf ${MAKEFILE_DIR}/target

.PHONY: lint
lint:  ## Run fmt and lint
	# typo
	typos
	# gitleaks ref. https://github.com/gitleaks/gitleaks
	gitleaks detect --source . -v
	# cargo fmt
	cargo fmt
	# cargo clippy
	cargo clippy
	# diff
	git diff --exit-code


.PHONY: test
test:  ## Run test
	@[ -x "${DOTLOCAL_BIN_DIR}/godotnev" ] || GOBIN="${DOTLOCAL_BIN_DIR}" go install github.com/joho/godotenv/cmd/godotenv@latest

	# Unit testing
	godotenv -f .test.env cargo test

.PHONY: ci
ci: generate lint test ## CI command set

.PHONY: vendor
vendor:  ## Vendor dependencies
	cargo update
	rm -rf vendor
	cargo vendor vendor
	git add --force vendor

.PHONY: build-remote
build-remote:  ## Run build binary workflow on GitHub Actions
	gh workflow run rust-build.yml --ref ${CURRENT_BRANCH}

.PHONY: build-remote-watch
build-remote-watch:  ## Watch building workflow on GitHub Actions
	gh run watch `gh run list --workflow=rust-build.yml --commit ${CURRENT_REVISION} --limit 1 --json databaseId --jq ".[]|.databaseId"` --exit-status

.PHONY: build-remote-download
build-remote-download: build-remote-watch ## Download build binary from GitHub Actions
	gh run download `gh run list --workflow=rust-build.yml --commit ${CURRENT_REVISION} --limit 1 --json databaseId --jq ".[]|.databaseId"` --dir ${MAKEFILE_DIR}/dist

.PHONY: release
release:  ## Upload release binary to GitHub Releases
	gh release upload `git describe --tags --abbrev=0` ./dist/*/quicport_*.*
