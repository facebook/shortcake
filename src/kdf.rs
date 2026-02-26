// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! HKDF-based key derivation.

use digest::core_api::BlockSizeUser;
use digest::Digest;
use hkdf::SimpleHkdf;

use crate::error::Error;

/// Derive a key using HKDF.
///
/// # Arguments
///
/// * `shared_secret` - The input keying material (IKM).
/// * `salt` - Optional salt value (can be empty).
/// * `info` - Application-specific context info.
/// * `out` - Buffer to write the derived key material into.
///
/// # Returns
///
/// `Ok(())` on success, `Err(Error::KdfError)` if expansion fails
/// (e.g., requested output too long).
pub fn derive_key<H: Digest + BlockSizeUser + Clone>(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let hk = SimpleHkdf::<H>::new(Some(salt), shared_secret);
    hk.expand(info, out).map_err(|_| Error::KdfError)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "x25519-sha256")]
    use super::*;

    #[cfg(feature = "x25519-sha256")]
    #[test]
    fn test_derive_key_deterministic() {
        use sha2::Sha256;

        let ss = [0xab; 32];
        let salt = b"test salt";
        let info = b"test info";

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        derive_key::<Sha256>(&ss, salt, info, &mut out1).unwrap();
        derive_key::<Sha256>(&ss, salt, info, &mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    #[cfg(feature = "x25519-sha256")]
    #[test]
    fn test_derive_key_different_inputs() {
        use sha2::Sha256;

        let ss = [0xab; 32];
        let salt = b"test salt";

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        derive_key::<Sha256>(&ss, salt, b"info1", &mut out1).unwrap();
        derive_key::<Sha256>(&ss, salt, b"info2", &mut out2).unwrap();

        assert_ne!(out1, out2);
    }
}
