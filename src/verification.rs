// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Verification code produced by the protocol.

use core::marker::PhantomData;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::ciphersuite::{CipherSuite, Kem};
use crate::error::Error;
use crate::sas::{Sas, DEFAULT_SAS_LEN};

/// A verification code produced by the protocol.
///
/// Both parties must compare their codes out-of-band. Call [`verify`](Self::verify)
/// with the other party's code bytes to confirm the match and obtain the shared secret.
///
/// `verify` consumes `self`, preventing retries.
pub struct VerificationCode<CS: CipherSuite> {
    pub(crate) sas: Sas,
    pub(crate) shared_secret: Option<<CS::Kem as Kem>::SharedSecret>,
    pub(crate) _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> VerificationCode<CS> {
    /// Returns the verification code bytes for display or transmission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.sas.as_bytes()[..DEFAULT_SAS_LEN]
    }

    /// Verify that the other party's code matches.
    ///
    /// On success, returns the shared secret. On failure, returns an error.
    /// Consumes `self` in either case, preventing retries.
    pub fn verify(mut self, other: &[u8]) -> Result<<CS::Kem as Kem>::SharedSecret, Error> {
        let ours = &self.sas.as_bytes()[..DEFAULT_SAS_LEN];
        if other.len() != DEFAULT_SAS_LEN || !bool::from(ours.ct_eq(other)) {
            return Err(Error::VerificationFailed);
        }
        self.shared_secret.take().ok_or(Error::VerificationFailed)
    }
}

impl<CS: CipherSuite> Drop for VerificationCode<CS> {
    fn drop(&mut self) {
        if let Some(ref mut ss) = self.shared_secret {
            ss.zeroize();
        }
    }
}
