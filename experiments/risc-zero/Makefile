.PHONY: build test clean cycles setup

# Dev mode - fast execution, no real proofs
export RISC0_DEV_MODE=1

build:
	cargo build

test:
	cargo test -- --nocapture

# Cycle count specifically
cycles:
	rm -f profile.pb && RISC0_PPROF_OUT=./profile.pb cargo test --release test_p256_ecdsa_cycles -- --nocapture && ~/go/bin/go tool pprof -text profile.pb
	#rm -f profile.pb && RISC0_PPROF_OUT=./profile.pb cargo test --release test_p384_ecdsa_cycles -- --nocapture && ~/go/bin/go tool pprof -text profile.pb
	#rm -f profile.pb && RISC0_PPROF_OUT=./profile.pb cargo test --release test_gcp_attestation_cycle_count -- --nocapture && ~/go/bin/go tool pprof -text profile.pb
	#rm -f profile.pb && RISC0_PPROF_OUT=./profile.pb cargo test --release test_nitro_attestation_cycle_count -- --nocapture && ~/go/bin/go tool pprof -text profile.pb

pprof-ui:
	~/go/bin/go tool pprof -http 0.0.0.0:8090 profile.pb 

clean:
	cargo clean

# Install prerequisites
setup:
	curl -L https://risczero.com/install | bash
	rzup install
