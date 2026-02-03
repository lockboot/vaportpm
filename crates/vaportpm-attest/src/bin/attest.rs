// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generate TPM attestation document
//!
//! Outputs a JSON attestation document to stdout.
//!
//! Usage:
//!   vaportpm-attest [NONCE_HEX]
//!
//! Nonce is determined by (in order of priority):
//! 1. Command-line argument (hex-encoded)
//! 2. Stdin if not a tty (hex-encoded, whitespace trimmed)
//! 3. Random 32-byte nonce

use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;
use vaportpm_attest::attest;

fn main() -> ExitCode {
    let nonce = match get_nonce() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match attest(&nonce) {
        Ok(json) => {
            println!("{}", json);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Get nonce from command-line argument, stdin, or generate random
fn get_nonce() -> Result<Vec<u8>, String> {
    let args: Vec<String> = std::env::args().collect();

    // 1. Check for command-line argument
    if args.len() > 1 {
        let hex_str = args[1].trim();
        return hex::decode(hex_str).map_err(|e| format!("invalid hex nonce: {}", e));
    }

    // 2. Check if stdin has data (not a tty)
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut input = String::new();
        stdin
            .lock()
            .read_to_string(&mut input)
            .map_err(|e| format!("failed to read nonce from stdin: {}", e))?;
        let hex_str = input.trim();
        if !hex_str.is_empty() {
            return hex::decode(hex_str).map_err(|e| format!("invalid hex nonce: {}", e));
        }
    }

    // 3. Generate random nonce
    Ok(random_nonce())
}

/// Generate a random 32-byte nonce using /dev/urandom
fn random_nonce() -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/urandom").expect("failed to open /dev/urandom");
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf)
        .expect("failed to read from /dev/urandom");
    buf.to_vec()
}
