// SPDX-License-Identifier: MIT OR Apache-2.0

//! vaportpm-attest — TPM attestation and PCR-bound key derivation
//!
//! Usage:
//!   vaportpm-attest attest [NONCE_HEX]   Attestation (JSON to stdout)
//!   vaportpm-attest derive <LABEL> <LEN> [--exclude <PCRS>]
//!                                        PCR-bound key derivation (hex to stdout)
//!
//! Attestation nonce is determined by (in order of priority):
//! 1. Argument after "attest" (hex-encoded)
//! 2. Stdin if not a tty (hex-encoded, whitespace trimmed)
//! 3. Random 32-byte nonce
//!
//! Derivation binds to all PCRs (0-23), less any `--exclude`d (comma-separated, e.g.
//! `--exclude 5,15`): a PCR that moves while the platform is the same one (the GPT a loader
//! rewrites on first boot) or that the caller doesn't want its keys to follow. The same TPM
//! at the same bound PCR state reproduces identical bytes; any change to a bound PCR yields
//! different output.

use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;
use vaportpm_attest::{attest, DeriveOps, Tpm};

const ALL_PCRS: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("attest") => cmd_attest(&args[2..]),
        Some("derive") => cmd_derive(&args[2..]),
        _ => {
            eprintln!("usage: vaportpm-attest <attest|derive>");
            eprintln!("  attest [NONCE_HEX]     Generate TPM attestation (JSON to stdout)");
            eprintln!("  derive <LABEL> <LEN> [--exclude <PCRS>]");
            eprintln!("                         PCR-bound key derivation (hex to stdout)");
            ExitCode::FAILURE
        }
    }
}

fn cmd_attest(args: &[String]) -> ExitCode {
    let nonce = match get_nonce(args) {
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

fn cmd_derive(args: &[String]) -> ExitCode {
    let excluded = match args {
        [_, _] => Vec::new(),
        [_, _, flag, list] if flag == "--exclude" => match parse_pcrs(list) {
            Ok(pcrs) => pcrs,
            Err(e) => {
                eprintln!("error: {}", e);
                return ExitCode::FAILURE;
            }
        },
        _ => {
            eprintln!("usage: vaportpm-attest derive <LABEL> <LEN> [--exclude <PCRS>]");
            return ExitCode::FAILURE;
        }
    };
    let pcrs: Vec<u8> = ALL_PCRS
        .iter()
        .copied()
        .filter(|p| !excluded.contains(p))
        .collect();

    let label = args[0].as_bytes();
    let len: usize = match args[1].parse() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("error: LEN must be a positive integer");
            return ExitCode::FAILURE;
        }
    };

    let mut tpm = match Tpm::open() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: failed to open TPM: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match tpm.derive_pcr_bound(&pcrs, label, len) {
        Ok(bytes) => {
            println!("{}", hex::encode(&bytes));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: derivation failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// PCR indices, comma-separated: each 0-23, none repeated.
fn parse_pcrs(list: &str) -> Result<Vec<u8>, String> {
    let mut pcrs = Vec::new();
    for item in list.split(',') {
        let pcr: u8 = item
            .trim()
            .parse()
            .ok()
            .filter(|p| ALL_PCRS.contains(p))
            .ok_or_else(|| format!("not a PCR (0-23): {:?}", item))?;
        if pcrs.contains(&pcr) {
            return Err(format!("PCR {} given twice", pcr));
        }
        pcrs.push(pcr);
    }
    Ok(pcrs)
}

fn get_nonce(args: &[String]) -> Result<Vec<u8>, String> {
    if !args.is_empty() {
        let hex_str = args[0].trim();
        return hex::decode(hex_str).map_err(|e| format!("invalid hex nonce: {}", e));
    }

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

    Ok(random_nonce())
}

fn random_nonce() -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/urandom").expect("failed to open /dev/urandom");
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf)
        .expect("failed to read from /dev/urandom");
    buf.to_vec()
}
