// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generate TPM attestation document
//!
//! Outputs a JSON attestation document to stdout.

use std::process::ExitCode;
use vaportpm_attest::attest;

fn main() -> ExitCode {
    // Generate a random nonce if none provided
    let nonce: Vec<u8> = (0..32).map(|_| rand()).collect();

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

/// Simple random byte generator using /dev/urandom
fn rand() -> u8 {
    use std::fs::File;
    use std::io::Read;

    thread_local! {
        static URANDOM: std::cell::RefCell<Option<File>> = const { std::cell::RefCell::new(None) };
    }

    URANDOM.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let file = borrow.get_or_insert_with(|| File::open("/dev/urandom").unwrap());
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf).unwrap();
        buf[0]
    })
}
