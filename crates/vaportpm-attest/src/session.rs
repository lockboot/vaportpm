// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authorization sessions and policy commands.
//!
//! Low-level building blocks for TPM authorization sessions and the policy assertions
//! layered onto them: start a trial or policy session, bind it to a PCR selection, and
//! read back the resulting policy digest. These are the primitives that higher-level
//! schemes (PCR-gated key derivation, sealing, policy-gated quote) build on; kept
//! `pub(crate)` until an external caller needs them.

use alloc::vec::Vec;
use anyhow::Result;

use crate::{CommandBuffer, Tpm, TpmAlg, TpmCc, TpmSt, TPM_RH_NULL};

/// Authorization-session and policy primitives.
pub(crate) trait SessionOps {
    /// `TPM2_StartAuthSession` for `session_type` (e.g. `TPM_SE_POLICY` / `TPM_SE_TRIAL`);
    /// returns the transient session handle.
    fn start_auth_session(&mut self, session_type: u8) -> Result<u32>;

    /// `TPM2_PolicyPCR` with an empty `pcrDigest`, binding the session to the *current*
    /// values of the PCRs named in `pcrs` (a marshalled `TPML_PCR_SELECTION`).
    fn policy_pcr(&mut self, session: u32, pcrs: &[u8]) -> Result<()>;

    /// `TPM2_PolicyGetDigest` — read the accumulated policy digest for `session`.
    fn policy_get_digest(&mut self, session: u32) -> Result<Vec<u8>>;
}

impl SessionOps for Tpm {
    /// `TPM2_StartAuthSession` — unsalted, unbound, SHA-256, no parameter encryption.
    /// The session nonces don't affect the policy digest or the HMAC output, so a fixed
    /// caller nonce keeps derivation deterministic.
    fn start_auth_session(&mut self, session_type: u8) -> Result<u32> {
        let command = CommandBuffer::new()
            .write_u32(TPM_RH_NULL) // tpmKey (unsalted)
            .write_u32(TPM_RH_NULL) // bind (unbound)
            .write_tpm2b(&[0u8; 32]) // nonceCaller
            .write_u16(0) // encryptedSalt (empty)
            .write_u8(session_type) // sessionType
            .write_u16(TpmAlg::Null as u16) // symmetric = NULL
            .write_u16(TpmAlg::Sha256 as u16) // authHash
            .finalize(TpmSt::NoSessions, TpmCc::StartAuthSession);
        let mut resp = self.transmit(&command)?;
        resp.read_u32() // sessionHandle (nonceTPM follows, unused)
    }

    /// `TPM2_PolicyPCR` — empty pcrDigest so the TPM binds the *current* PCR values.
    fn policy_pcr(&mut self, session: u32, pcrs: &[u8]) -> Result<()> {
        let command = CommandBuffer::new()
            .write_u32(session)
            .write_u16(0) // pcrDigest (empty -> TPM uses current PCRs)
            .write_bytes(pcrs) // pcrs (TPML_PCR_SELECTION)
            .finalize(TpmSt::NoSessions, TpmCc::PolicyPCR);
        self.transmit(&command)?;
        Ok(())
    }

    /// `TPM2_PolicyGetDigest`.
    fn policy_get_digest(&mut self, session: u32) -> Result<Vec<u8>> {
        let command = CommandBuffer::new()
            .write_u32(session)
            .finalize(TpmSt::NoSessions, TpmCc::PolicyGetDigest);
        let mut resp = self.transmit(&command)?;
        resp.read_tpm2b()
    }
}
