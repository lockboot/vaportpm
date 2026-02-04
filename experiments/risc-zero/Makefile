.PHONY: build test clean cycles setup

# Dev mode - fast execution, no real proofs
export RISC0_DEV_MODE=1

build:
	cargo build

test:
	cargo test -- --nocapture

# Cycle count specifically
cycles:
	RISC0_PPROF_OUT=./profile.pb cargo test test_nitro_attestation_cycle_count -- --nocapture && ~/go/bin/go tool pprof -text profile.pb

clean:
	cargo clean

# Install prerequisites
setup:
	curl -L https://risczero.com/install | bash
	rzup install
