// SPDX-License-Identifier: MIT OR Apache-2.0

//! PCR-gated key derivation.
//!
//! Derive arbitrary-length key material that is bound to the current PCR state and to
//! this TPM, namespaced by a caller-chosen label. Same TPM at the same PCR state
//! reproduces the identical bytes on every boot; any other state cannot obtain them.
//!
//! The binding is enforced by the TPM, not by the caller. A keyedhash HMAC key is
//! created in the owner hierarchy with `userWithAuth` cleared and an `authPolicy` equal
//! to a `TPM2_PolicyPCR` digest over the full PCR set; using the key (HMAC) therefore
//! requires a policy session in which the TPM itself reads the *live* PCRs. A caller in
//! a different state cannot satisfy the policy (the TPM measures reality, not a supplied
//! value), so it cannot exercise the key — reconstructing the key material via a forged
//! template does not help, because the policy check happens at use time.
//!
//! The gated key is a KDF root: `HMAC(key, label || counter)` yields the requested
//! bytes, and `label` namespaces independent derivations from the one PCR-gated root.

use alloc::vec::Vec;
use anyhow::{bail, Result};

use crate::pcr::pcr_selection;
use crate::session::SessionOps;
use crate::{
    CommandBuffer, ObjectAttributes, Tpm, TpmAlg, TpmCc, TpmSt, TPM_RH_OWNER, TPM_SE_POLICY,
    TPM_SE_TRIAL,
};

/// TPM_ALG_KEYEDHASH / TPM_ALG_HMAC — not in the [`TpmAlg`] enum (asym/sym algs only).
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_HMAC: u16 = 0x0005;

/// PCR-gated key derivation extension trait.
pub trait DeriveOps {
    /// Derive `len` bytes bound to the SHA-256 values of the PCRs named in `pcr_indices`
    /// and to this TPM, namespaced by `label`. Deterministic across reboots while those
    /// PCRs and the TPM seed are unchanged; unobtainable in any other state. The caller
    /// chooses which PCRs identify "the same platform" — e.g. code/policy PCRs while
    /// excluding volatile ones like PCR 5 (GPT). `label` separates independent
    /// derivations from the same gated root.
    fn derive_pcr_bound(&mut self, pcr_indices: &[u8], label: &[u8], len: usize)
        -> Result<Vec<u8>>;
}

impl DeriveOps for Tpm {
    fn derive_pcr_bound(
        &mut self,
        pcr_indices: &[u8],
        label: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        let pcrs = pcr_selection(pcr_indices, TpmAlg::Sha256);
        let auth_policy = self.pcr_policy_digest(&pcrs)?;
        let template = build_keyedhash_template(&auth_policy);
        let key = self.create_keyedhash_primary(TPM_RH_OWNER, &template)?;

        // Flush the transient key even if a derivation step fails.
        let result = self.hmac_kdf(key, &pcrs, label, len);
        let _ = self.flush_context(key);
        result
    }
}

impl Tpm {
    /// `HMAC(key, label || counter)` stretched to `len` bytes, over a single policy
    /// session. Each authorized HMAC consumes the session's policy digest, so
    /// `PolicyPCR` is re-satisfied before every block (the TPM re-reads the live PCRs);
    /// the session itself is created once and flushed at the end.
    fn hmac_kdf(&mut self, key: u32, pcrs: &[u8], label: &[u8], len: usize) -> Result<Vec<u8>> {
        let session = self.start_auth_session(TPM_SE_POLICY)?;
        let result = (|| {
            let mut out = Vec::with_capacity(len);
            let mut counter: u32 = 0;
            while out.len() < len {
                self.policy_pcr(session, pcrs)?; // (re)satisfy before each authorized use
                let mut msg = Vec::with_capacity(label.len() + 4);
                msg.extend_from_slice(label);
                msg.extend_from_slice(&counter.to_be_bytes());
                let block = self.tpm2_hmac_policy(key, session, &msg)?;
                if block.len() != 32 {
                    bail!("TPM2_HMAC returned {} bytes, expected 32", block.len());
                }
                out.extend_from_slice(&block);
                counter += 1;
            }
            out.truncate(len);
            Ok(out)
        })();
        let _ = self.flush_context(session);
        result
    }

    /// `authPolicy` digest for `pcrs` in the current state, via a trial session (the TPM
    /// computes the exact `PolicyPCR` digest for us).
    fn pcr_policy_digest(&mut self, pcrs: &[u8]) -> Result<Vec<u8>> {
        let session = self.start_auth_session(TPM_SE_TRIAL)?;
        let digest = (|| {
            self.policy_pcr(session, pcrs)?;
            self.policy_get_digest(session)
        })();
        let _ = self.flush_context(session);
        digest
    }

    /// `TPM2_CreatePrimary` for the keyedhash template; returns the transient handle.
    fn create_keyedhash_primary(&mut self, hierarchy: u32, template: &[u8]) -> Result<u32> {
        let command = CommandBuffer::new()
            .write_u32(hierarchy)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE): empty userAuth + empty data
            .write_u16(4)
            .write_u16(0)
            .write_u16(0)
            .write_tpm2b(template) // inPublic
            .write_u16(0) // outsideInfo (empty)
            .write_u32(0) // creationPCR: empty — creation-data/CertifyCreation only,
            //               does NOT bind the key (binding is authPolicy + policy session)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;
        resp.read_u32() // objectHandle (parameters follow, unused)
    }

    /// `TPM2_HMAC` of `data` through the keyedhash key, authorized by a policy `session`.
    fn tpm2_hmac_policy(&mut self, key: u32, session: u32, data: &[u8]) -> Result<Vec<u8>> {
        let command = CommandBuffer::new()
            .write_u32(key)
            .write_auth_policy_session(session)
            .write_tpm2b(data) // buffer (TPM2B_MAX_BUFFER)
            .write_u16(TpmAlg::Null as u16) // hashAlg NULL — key carries its HMAC scheme
            .finalize(TpmSt::Sessions, TpmCc::Hmac);
        let mut resp = self.transmit(&command)?;
        let _param_size = resp.read_u32()?;
        resp.read_tpm2b()
    }
}

/// TPMT_PUBLIC for a keyedhash HMAC primary gated by `auth_policy`. `userWithAuth` is
/// cleared so use requires the policy session; NULL `unique` (the key material need not
/// carry the PCR state — the policy session enforces it at use time).
fn build_keyedhash_template(auth_policy: &[u8]) -> Vec<u8> {
    let attrs = ObjectAttributes::new()
        .fixed_tpm()
        .fixed_parent()
        .sensitive_data_origin()
        .sign_encrypt();

    CommandBuffer::new()
        .write_u16(TPM_ALG_KEYEDHASH) // type
        .write_u16(TpmAlg::Sha256 as u16) // nameAlg
        .write_u32(attrs.value()) // objectAttributes (no userWithAuth)
        .write_tpm2b(auth_policy) // authPolicy = PolicyPCR digest
        // parameters (TPMS_KEYEDHASH_PARMS): scheme HMAC over SHA-256
        .write_u16(TPM_ALG_HMAC)
        .write_u16(TpmAlg::Sha256 as u16)
        // unique (TPM2B_DIGEST) - empty
        .write_u16(0)
        .into_vec()
}
