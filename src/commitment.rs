// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Commitment scheme for the protocol.

use digest::{Digest, Output};
use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::Nonce;

/// Compute a commitment over an encapsulation key and nonce.
///
/// The commitment is `Hash("shortcake-commitment-v1" || len(ek_bytes) || ek_bytes || nonce)`,
/// where `len(ek_bytes)` is encoded as a u64 in big-endian. The length prefix ensures
/// unambiguous parsing for variable-length encapsulation keys.
pub fn commit<H: Digest>(ek_bytes: &[u8], nonce: &Nonce) -> Output<H> {
    let mut hasher = H::new();
    hasher.update(b"shortcake-commitment-v1");
    hasher.update((ek_bytes.len() as u64).to_be_bytes());
    hasher.update(ek_bytes);
    hasher.update(nonce);
    hasher.finalize()
}

/// Verify a commitment.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Returns
///
/// `Ok(())` if the commitment matches, `Err(Error::CommitmentMismatch)` otherwise.
pub fn open<H: Digest>(ek_bytes: &[u8], nonce: &Nonce, expected: &Output<H>) -> Result<(), Error> {
    let computed = commit::<H>(ek_bytes, nonce);
    if computed.as_slice().ct_eq(expected.as_slice()).into() {
        Ok(())
    } else {
        Err(Error::CommitmentMismatch)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "xwing")]
    use super::*;

    #[cfg(feature = "xwing")]
    #[test]
    fn test_commit_open_roundtrip() {
        use sha3::Sha3_256;

        let ek = [1u8; 32];
        let nonce = [2u8; 32];

        let commitment = commit::<Sha3_256>(&ek, &nonce);
        assert!(open::<Sha3_256>(&ek, &nonce, &commitment).is_ok());
    }

    #[cfg(feature = "xwing")]
    #[test]
    fn test_commit_open_wrong_nonce() {
        use sha3::Sha3_256;

        let ek = [1u8; 32];
        let nonce = [2u8; 32];
        let wrong_nonce = [3u8; 32];

        let commitment = commit::<Sha3_256>(&ek, &nonce);
        assert_eq!(
            open::<Sha3_256>(&ek, &wrong_nonce, &commitment),
            Err(Error::CommitmentMismatch)
        );
    }
}
