.PHONY: all build release-x86 check test fmt fmt-check clippy doc clean ci coverage setup-coverage

all: build

build:
	cargo build --workspace --release

release-x86:
	cargo build --workspace --release --target x86_64-unknown-linux-musl

release-aarch64:
	cargo build --workspace --release --target aarch64-unknown-linux-musl

check:
	cargo check --workspace --all-targets

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

clean:
	cargo clean

ci: fmt-check check clippy test doc

setup-coverage:
	rustup component add llvm-tools-preview
	cargo install cargo-llvm-cov

coverage-html:
	cargo llvm-cov -p vaportpm-verify --html
	@echo "Coverage report: target/llvm-cov/html/index.html"

coverage-text:
	cargo llvm-cov -p vaportpm-verify

rustup:
	rustup default stable