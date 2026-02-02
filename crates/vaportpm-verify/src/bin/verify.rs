// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify TPM attestation document
//!
//! Reads attestation JSON from a file or stdin, verifies it,
//! and outputs the verification result as JSON.

use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use vaportpm_verify::verify_attestation_json;

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
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}
