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
use crate::sas::hash_fields;
use crate::Nonce;

/// Domain separation string for commitments.
const COMMITMENT_DOMAIN_SEPARATOR: &[u8] = b"shortcake-commitment-v1";

/// Compute a commitment over an encapsulation key and nonce.
///
/// All fields are length-prefixed for unambiguous parsing.
pub fn commit<H: Digest>(ek_bytes: &[u8], nonce: &Nonce) -> Output<H> {
    hash_fields::<H>(COMMITMENT_DOMAIN_SEPARATOR, &[ek_bytes, nonce])
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
