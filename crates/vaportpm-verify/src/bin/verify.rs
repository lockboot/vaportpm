// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify TPM attestation document
//!
//! Reads attestation JSON from a file or stdin, verifies it,
//! and outputs the verification result as JSON: the verified PCRs, and the attestation's
//! GPT digests passed through as replay input (the quote does not cover them; a PCR replay
//! that uses them is checked against the verified PCRs).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use serde::Serialize;
use vaportpm_verify::{
    normalize_attestation_input, verify_attestation_output, AttestationOutput, CloudProvider,
    GptDigests, UnixTime, VerificationResult,
};

/// JSON-friendly output with hex-encoded binary fields
#[derive(Serialize)]
struct VerificationResultJson {
    nonce: String,
    provider: CloudProvider,
    /// PCR values grouped by algorithm: {"sha256": {"0": "abc...", ...}, "sha384": {...}}
    pcrs: BTreeMap<String, BTreeMap<u8, String>>,
    /// The boot disk's H(UEFI_GPT_DATA) per bank, from the attestation (replay input)
    gpt: GptDigests,
}

impl VerificationResultJson {
    fn new(result: VerificationResult, gpt: GptDigests) -> Self {
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
            gpt,
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

    let output: AttestationOutput = match normalize_attestation_input(&json)
        .map_err(|e| e.to_string())
        .and_then(|j| serde_json::from_str(&j).map_err(|e| e.to_string()))
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match verify_attestation_output(&output, UnixTime::now()) {
        Ok(result) => {
            let json_result = VerificationResultJson::new(result, output.gpt);
            println!("{}", serde_json::to_string_pretty(&json_result).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}
