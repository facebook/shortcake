// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! X25519 + SHA-256 ciphersuite implementation.
//!
//! This module provides a ready-to-use ciphersuite using X25519 (as a KEM)
//! and SHA-256 for hashing.

use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, Kem};

/// X25519 implemented as a KEM.
///
/// Encapsulation generates an ephemeral keypair, performs DH with the
/// recipient's public key, and returns the ephemeral public key as the
/// ciphertext and the DH result as the shared secret.
#[derive(Debug, Clone, Copy)]
pub struct X25519Kem;

/// X25519 shared secret (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret([u8; 32]);

impl AsRef<[u8]> for X25519SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// X25519 decapsulation (private) key.
///
/// Stores the raw 32-byte secret to enable proper zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519DecapsulationKey {
    bytes: [u8; 32],
}

impl X25519DecapsulationKey {
    /// Create a new decapsulation key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a new random decapsulation key.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        Self {
            bytes: secret.to_bytes(),
        }
    }

    /// Get the corresponding encapsulation (public) key.
    pub fn encapsulation_key(&self) -> X25519EncapsulationKey {
        let secret = StaticSecret::from(self.bytes);
        X25519EncapsulationKey(PublicKey::from(&secret))
    }

    /// Get the internal static secret for DH operations.
    fn to_static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.bytes)
    }
}

/// X25519 encapsulation (public) key.
#[derive(Clone)]
pub struct X25519EncapsulationKey(PublicKey);

impl X25519EncapsulationKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }

    /// Get the raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl AsRef<[u8]> for X25519EncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// X25519 ciphertext (ephemeral public key).
#[derive(Clone)]
pub struct X25519Ciphertext(PublicKey);

impl X25519Ciphertext {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }

    /// Get the raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl AsRef<[u8]> for X25519Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Error type for X25519 KEM operations.
#[derive(Debug, Clone, Copy)]
pub struct X25519KemError;

impl core::fmt::Display for X25519KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "X25519 KEM operation failed")
    }
}

impl Kem for X25519Kem {
    type EncapsulationKey = X25519EncapsulationKey;
    type DecapsulationKey = X25519DecapsulationKey;
    type Ciphertext = X25519Ciphertext;
    type SharedSecret = X25519SharedSecret;
    type Error = X25519KemError;

    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        // Generate ephemeral keypair
        let ephemeral_secret = StaticSecret::random_from_rng(rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // DH with recipient's public key
        let shared = ephemeral_secret.diffie_hellman(&ek.0);

        Ok((
            X25519Ciphertext(ephemeral_public),
            X25519SharedSecret(shared.to_bytes()),
        ))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        // DH with the ciphertext (ephemeral public key)
        let secret = dk.to_static_secret();
        let shared = secret.diffie_hellman(&ct.0);
        Ok(X25519SharedSecret(shared.to_bytes()))
    }
}

/// X25519 + SHA-256 ciphersuite.
#[derive(Debug, Clone, Copy)]
pub struct X25519Sha256;

impl CipherSuite for X25519Sha256 {
    type Kem = X25519Kem;
    type Hash = sha2::Sha256;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let mut rng = rand::thread_rng();

        // Generate keypair
        let dk = X25519DecapsulationKey::generate(&mut rng);
        let ek = dk.encapsulation_key();

        // Encapsulate
        let (ct, ss1) = X25519Kem::encaps(&ek, &mut rng).unwrap();

        // Decapsulate
        let ss2 = X25519Kem::decaps(&dk, &ct).unwrap();

        // Shared secrets must match
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }
}
