// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Short Authenticated String (SAS) derivation.
//!
//! The SAS is a truncated value that both parties compute and compare
//! out-of-band (e.g., by reading digits aloud) to authenticate the exchange.

use digest::Digest;

use crate::Nonce;

/// The length of the SAS in bytes (40 bits).
pub const SAS_LEN: usize = 5;

/// A 40-bit Short Authenticated String.
///
/// The raw bytes can be encoded by the caller in any format
/// (e.g., base32, decimal digits, emoji).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas(pub(crate) [u8; SAS_LEN]);

impl Sas {
    /// Returns the raw SAS bytes.
    pub fn as_bytes(&self) -> &[u8; SAS_LEN] {
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
/// sas = responder_nonce[0..5] XOR hash[0..5]
/// ```
///
/// The length prefix on `ct_bytes` ensures unambiguous parsing for
/// variable-length ciphertext types.
pub fn compute_sas<H: Digest>(
    responder_nonce: &Nonce,
    initiator_nonce: &Nonce,
    ct_bytes: &[u8],
) -> Sas {
    let mut hasher = H::new();
    hasher.update(b"shortcake-sas-v1");
    hasher.update(initiator_nonce);
    hasher.update((ct_bytes.len() as u64).to_be_bytes());
    hasher.update(ct_bytes);
    let hash = hasher.finalize();

    let mut sas = [0u8; SAS_LEN];
    for i in 0..SAS_LEN {
        sas[i] = responder_nonce[i] ^ hash[i];
    }
    Sas(sas)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "x25519-sha256")]
    use super::*;

    #[cfg(feature = "x25519-sha256")]
    #[test]
    fn test_sas_deterministic() {
        use sha2::Sha256;

        let responder_nonce = [1u8; 32];
        let initiator_nonce = [2u8; 32];
        let ct = [3u8; 32];

        let sas1 = compute_sas::<Sha256>(&responder_nonce, &initiator_nonce, &ct);
        let sas2 = compute_sas::<Sha256>(&responder_nonce, &initiator_nonce, &ct);

        assert_eq!(sas1, sas2);
    }

    #[cfg(feature = "x25519-sha256")]
    #[test]
    fn test_sas_changes_with_inputs() {
        use sha2::Sha256;

        let responder_nonce = [1u8; 32];
        let initiator_nonce = [2u8; 32];
        let ct = [3u8; 32];

        let sas1 = compute_sas::<Sha256>(&responder_nonce, &initiator_nonce, &ct);

        let mut different_nonce = responder_nonce;
        different_nonce[0] = 99;
        let sas2 = compute_sas::<Sha256>(&different_nonce, &initiator_nonce, &ct);

        assert_ne!(sas1, sas2);
    }
}
