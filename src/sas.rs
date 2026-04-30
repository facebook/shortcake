// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! SAS and session key derivation.

use digest::{Digest, Output};

use crate::Nonce;

/// Domain separation string for SAS derivation.
const SAS_DOMAIN_SEPARATOR: &[u8] = b"shortcake-sas-v1";

/// Domain separation string for session key derivation.
const SESSION_KEY_DOMAIN_SEPARATOR: &[u8] = b"shortcake-session-key-v1";

/// Hash a domain separator and a sequence of fields, each length-prefixed
/// with its byte length as a big-endian u64.
pub(crate) fn hash_fields<H: Digest>(domain_sep: &[u8], fields: &[&[u8]]) -> Output<H> {
    let mut h = H::new();
    h.update(domain_sep);
    for field in fields {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.finalize()
}

/// The maximum length of the SAS in bytes, equal to the nonce size.
pub const SAS_MAX_LEN: usize = core::mem::size_of::<Nonce>();

/// A Short Authenticated String.
///
/// Contains the full [`SAS_MAX_LEN`]-byte SAS value. Callers should
/// truncate to their desired length when displaying or comparing
/// out-of-band.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Sas(pub(crate) [u8; SAS_MAX_LEN]);

impl Sas {
    /// Returns the full raw SAS bytes.
    ///
    /// Truncate to a prefix of the desired length before displaying.
    pub fn as_bytes(&self) -> &[u8; SAS_MAX_LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for Sas {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for Sas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sas({:02x?})", self.0)
    }
}

/// Compute the SAS from protocol values.
///
/// The computation is:
/// ```text
/// hash = Hash("shortcake-sas-v1" || initiator_nonce || len(ct_bytes) || ct_bytes)
/// sas = responder_nonce XOR hash[0..SAS_MAX_LEN]
/// ```
///
/// The length prefix on `ct_bytes` ensures unambiguous parsing for
/// variable-length ciphertext types.
pub fn compute_sas<H: Digest>(
    responder_nonce: &Nonce,
    initiator_nonce: &Nonce,
    ct_bytes: &[u8],
) -> Sas {
    let hash = hash_fields::<H>(SAS_DOMAIN_SEPARATOR, &[initiator_nonce, ct_bytes]);

    let mut sas = [0u8; SAS_MAX_LEN];
    for i in 0..SAS_MAX_LEN {
        sas[i] = responder_nonce[i] ^ hash[i];
    }
    Sas(sas)
}

/// Derive a session key from the full protocol transcript.
///
/// Inputs are ordered by protocol message flow:
/// `Hash(domain_sep || ek || ct || responder_nonce || initiator_nonce || kem_ss)`
pub fn derive_session_key<H: Digest>(
    ek_bytes: &[u8],
    ct_bytes: &[u8],
    responder_nonce: &Nonce,
    initiator_nonce: &Nonce,
    kem_ss: &[u8],
) -> Output<H> {
    hash_fields::<H>(
        SESSION_KEY_DOMAIN_SEPARATOR,
        &[ek_bytes, ct_bytes, responder_nonce, initiator_nonce, kem_ss],
    )
}

// Ensure the SAS max length does not exceed the minimum expected hash output size.
const _: () = assert!(
    SAS_MAX_LEN <= 32,
    "SAS_MAX_LEN must not exceed the minimum expected hash output size"
);

#[cfg(test)]
mod tests {
    #[cfg(feature = "xwing")]
    use super::*;

    #[cfg(feature = "xwing")]
    #[test]
    fn test_sas_deterministic() {
        use sha3::Sha3_256;

        let responder_nonce = [1u8; 32];
        let initiator_nonce = [2u8; 32];
        let ct = [3u8; 32];

        let sas1 = compute_sas::<Sha3_256>(&responder_nonce, &initiator_nonce, &ct);
        let sas2 = compute_sas::<Sha3_256>(&responder_nonce, &initiator_nonce, &ct);

        assert_eq!(sas1, sas2);
    }

    #[cfg(feature = "xwing")]
    #[test]
    fn test_sas_changes_with_inputs() {
        use sha3::Sha3_256;

        let responder_nonce = [1u8; 32];
        let initiator_nonce = [2u8; 32];
        let ct = [3u8; 32];

        let sas1 = compute_sas::<Sha3_256>(&responder_nonce, &initiator_nonce, &ct);

        let mut different_nonce = responder_nonce;
        different_nonce[0] = 99;
        let sas2 = compute_sas::<Sha3_256>(&different_nonce, &initiator_nonce, &ct);

        assert_ne!(sas1, sas2);
    }
}
