// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Traits for KEM and ciphersuite abstraction.

use core::fmt::Debug;

use digest::Digest;
use rand_core::CryptoRng;
use zeroize::Zeroize;

/// A Key Encapsulation Mechanism (KEM).
///
/// This trait abstracts over KEM operations, allowing the protocol to be
/// generic over different KEMs (e.g., X25519-as-KEM, ML-KEM, hybrid KEMs).
pub trait Kem {
    /// The encapsulation (public) key type.
    type EncapsulationKey: AsRef<[u8]> + Clone + Zeroize;

    /// The decapsulation (private) key type.
    type DecapsulationKey: Zeroize;

    /// The ciphertext type produced by encapsulation.
    type Ciphertext: AsRef<[u8]> + Clone + Zeroize;

    /// The shared secret type.
    type SharedSecret: AsRef<[u8]> + Zeroize;

    /// Error type for KEM operations.
    type Error: Debug;

    /// Generate a new KEM keypair.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (decapsulation_key, encapsulation_key).
    fn generate(rng: &mut impl CryptoRng) -> (Self::DecapsulationKey, Self::EncapsulationKey);

    /// Encapsulate to produce a ciphertext and shared secret.
    ///
    /// # Arguments
    ///
    /// * `ek` - The recipient's encapsulation (public) key.
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret) on success.
    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;

    /// Decapsulate a ciphertext to recover the shared secret.
    ///
    /// # Arguments
    ///
    /// * `dk` - The decapsulation (private) key.
    /// * `ct` - The ciphertext to decapsulate.
    ///
    /// # Returns
    ///
    /// The shared secret on success.
    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error>;
}

/// A ciphersuite bundles a KEM and hash function for use in the protocol.
pub trait CipherSuite {
    /// The KEM used for key encapsulation.
    type Kem: Kem;

    /// The hash function used for commitments and SAS derivation.
    type Hash: Digest + Clone;
}
