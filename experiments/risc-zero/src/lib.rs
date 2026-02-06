// SPDX-License-Identifier: MIT OR Apache-2.0

//! RISC Zero ZK experiment for vaportpm attestation verification
//!
//! This crate provides an experimental integration of vaportpm attestation
//! verification with RISC Zero's zkVM. The goal is to measure cycle counts
//! and understand the complexity of running attestation verification in ZK.
//!
//! # Structure
//!
//! - `inputs`: Public input types committed by the ZK circuit
//! - `host`: Host-side utilities for running the zkVM
//!
//! # Usage
//!
//! Run the cycle count tests:
//! ```bash
//! cd experiments/risc-zero
//! make cycles
//! ```

pub mod host;
pub mod inputs;

pub use inputs::ZkPublicInputs;
