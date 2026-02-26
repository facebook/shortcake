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

        // Reject low-order public keys (non-contributory shared secret).
        // REVIEW COMMENT: was_contributory() checks that the DH output is not all-zero.
        // Because x25519_dalek clamps the scalar (nonzero, multiple of 8), [s]P = 0
        // iff P has small order (dividing cofactor 8). All 8 small-order points on
        // Curve25519 produce the all-zero output, so this single check is sufficient —
        // no separate pre-check of the input point against the identity is needed.
        if !shared.was_contributory() {
            return Err(X25519KemError);
        }

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

        // Reject low-order ciphertexts (non-contributory shared secret).
        if !shared.was_contributory() {
            return Err(X25519KemError);
        }

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

    #[test]
    fn test_decaps_rejects_low_order_point() {
        let dk = X25519DecapsulationKey::from_bytes([1u8; 32]);
        let low_order_ct = X25519Ciphertext::from_bytes([0u8; 32]);
        assert!(X25519Kem::decaps(&dk, &low_order_ct).is_err());
    }

    #[test]
    fn test_encaps_rejects_low_order_key() {
        let mut rng = rand::thread_rng();
        let low_order_ek = X25519EncapsulationKey::from_bytes([0u8; 32]);
        assert!(X25519Kem::encaps(&low_order_ek, &mut rng).is_err());
    }

    // REVIEW_TEST: Sanity check that all small-order u-coordinates produce non-contributory
    // DH outputs. The Montgomery ladder doesn't distinguish curve from twist, so we must
    // cover both. The curve (cofactor 8) has 8 torsion points giving 4 distinct finite
    // u-coordinates (negatives share u, identity has none). The twist (cofactor 4) adds
    // 1 more (p-1). That's 5 distinct u-values mod p; 0 and 1 each have a non-canonical
    // byte representation below 2^255 (at p and p+1), giving 7 byte patterns total.
    #[test]
    fn test_all_small_order_points_rejected() {
        let small_order_points: [[u8; 32]; 7] = [
            // u = 0 (identity in X25519 encoding)
            [0; 32],
            // u = 1 (order 4)
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            // u = 325606250916557431795983626356110631294008115727848805560023387167927233504
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            // u = 39382357235489614581723060781553021112529911719440698176882885853963445705823
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
            // u = p - 1 (twist torsion; twist has cofactor 4, also killed by clamped scalar)
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            // u = p (non-canonical representation of u = 0)
            [
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            // u = p + 1 (non-canonical representation of u = 1)
            [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ];

        let dk = X25519DecapsulationKey::from_bytes([9u8; 32]);
        for (i, point) in small_order_points.iter().enumerate() {
            let ct = X25519Ciphertext::from_bytes(*point);
            assert!(
                X25519Kem::decaps(&dk, &ct).is_err(),
                "small-order point {} should be rejected",
                i
            );
        }
    }
}
