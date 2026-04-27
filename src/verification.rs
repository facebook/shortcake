// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Protocol output containing the SAS code and shared secret.

use core::marker::PhantomData;

use zeroize::Zeroize;

use crate::ciphersuite::{CipherSuite, Kem};
use crate::sas::Sas;

/// Output of a completed protocol run, containing a SAS code and a shared secret.
///
/// Both parties must compare their SAS codes out-of-band (e.g., by reading
/// digits aloud, displaying an emoji sequence). The full 32-byte SAS is
/// returned; consumers should truncate to their desired security level
/// (e.g., `&output.sas_code()[..5]` for 40-bit security).
///
/// # Security Warning
///
/// The shared secret **must not** be used until both parties have confirmed
/// their SAS codes match. Using the secret before out-of-band verification
/// provides no authentication guarantee — an active attacker could have
/// substituted their own key material.
pub struct ProtocolOutput<CS: CipherSuite> {
    pub(crate) sas: Sas,
    pub(crate) shared_secret: Option<<CS::Kem as Kem>::SharedSecret>,
    pub(crate) _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> ProtocolOutput<CS> {
    /// Returns the full SAS code bytes (32 bytes).
    ///
    /// Consumers should truncate this to their desired comparison
    /// length (e.g., `&sas_code[..5]` for 40-bit security).
    pub fn sas_code(&self) -> &[u8] {
        self.sas.as_bytes()
    }

    /// Consume this output and return the shared secret.
    ///
    /// # Security Warning
    ///
    /// The shared secret MUST NOT be used until both parties have
    /// compared their SAS codes out-of-band and confirmed they match.
    /// Using the secret before verification provides no authentication
    /// guarantee — an active attacker could have substituted their own
    /// key material.
    pub fn into_shared_secret(mut self) -> <CS::Kem as Kem>::SharedSecret {
        self.shared_secret
            .take()
            .expect("into_shared_secret called twice")
    }
}

impl<CS: CipherSuite> Drop for ProtocolOutput<CS> {
    fn drop(&mut self) {
        if let Some(ref mut ss) = self.shared_secret {
            ss.zeroize();
        }
    }
}
