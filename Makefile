.PHONY: all build release-x86 release-aarch64 check test fmt fmt-check clippy doc clean ci \
	setup-coverage coverage-html coverage-text

# Shared build harness (docker images + DOCKER_RUN plumbing). Vendored byte-identically from
# stage0/build.mk (the canonical source) via the workspace `make sync-harness`; do not hand-edit.
# `make check-harness` guards against drift. Every cargo recipe runs inside lockboot:build so the
# build is cc-free-by-design and reproducible (rust-lld + the shared /src/.cargo, /src/.rustup).
include build.mk

# vaportpm is a gnu-host repo: the std tooling (attest/verify CLIs) and the test suite build for the
# host target inside the image (glibc is present there); musl is opt-in via the release-* targets.
CARGO = $(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) cargo

all: build

build: docker-build-base
	$(CARGO) build --workspace --release

release-x86: docker-build-base
	$(CARGO) build --workspace --release --target x86_64-unknown-linux-musl

release-aarch64: docker-build-base
	$(CARGO) build --workspace --release --target aarch64-unknown-linux-musl

check: docker-build-base
	$(CARGO) check --workspace --all-targets

test: docker-build-base
	$(CARGO) test --workspace

fmt: docker-build-base
	$(CARGO) fmt --all

fmt-check: docker-build-base
	$(CARGO) fmt --all -- --check

clippy: docker-build-base
	$(CARGO) clippy --workspace --all-targets -- -D warnings

doc: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) -e RUSTDOCFLAGS="-D warnings" $(BUILD_IMAGE) cargo doc --workspace --no-deps

clean: docker-build-base
	$(CARGO) clean

ci: fmt-check check clippy test doc

setup-coverage: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "rustup component add llvm-tools-preview && cargo install cargo-llvm-cov"

coverage-html: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) cargo llvm-cov -p vaportpm-verify --html
	@echo "Coverage report: target/llvm-cov/html/index.html"

coverage-text: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) cargo llvm-cov -p vaportpm-verify
