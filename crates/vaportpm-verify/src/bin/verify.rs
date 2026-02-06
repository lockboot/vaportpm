// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify TPM attestation document
//!
//! Reads attestation JSON from a file or stdin, verifies it,
//! and outputs the verification result as JSON.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use serde::Serialize;
use vaportpm_verify::{verify_attestation_json, CloudProvider, VerificationResult};

/// JSON-friendly output with hex-encoded binary fields
#[derive(Serialize)]
struct VerificationResultJson {
    nonce: String,
    provider: CloudProvider,
    /// PCR values grouped by algorithm: {"sha256": {"0": "abc...", ...}, "sha384": {...}}
    pcrs: BTreeMap<String, BTreeMap<u8, String>>,
}

impl From<VerificationResult> for VerificationResultJson {
    fn from(result: VerificationResult) -> Self {
        let mut pcr_map = BTreeMap::new();
        for (idx, value) in result.pcrs.values().enumerate() {
            pcr_map.insert(idx as u8, hex::encode(value));
        }

        let mut pcrs = BTreeMap::new();
        pcrs.insert(result.pcrs.algorithm().to_string(), pcr_map);

        VerificationResultJson {
            nonce: hex::encode(result.nonce),
            provider: result.provider,
            pcrs,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // Read attestation JSON from file or stdin
    let json = match args.get(1) {
        Some(path) if path != "-" => match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("error: failed to read file: {}", e);
                return ExitCode::FAILURE;
            }
        },
        _ => {
            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                eprintln!("error: failed to read stdin: {}", e);
                return ExitCode::FAILURE;
            }
            input
        }
    };

    match verify_attestation_json(&json) {
        Ok(result) => {
            let json_result = VerificationResultJson::from(result);
            println!("{}", serde_json::to_string_pretty(&json_result).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}
