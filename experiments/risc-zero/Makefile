.PHONY: build test clean cycles setup

# Dev mode - fast execution, no real proofs
export RISC0_DEV_MODE=1

build:
	cargo build

test:
	cargo test -- --nocapture

# Cycle count specifically
cycles:
	cargo test cycle_count -- --nocapture

clean:
	cargo clean

# Install prerequisites
setup:
	curl -L https://risczero.com/install | bash
	rzup install
