// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! ML-KEM-768 + SHA-256 ciphersuite implementation.
//!
//! This module provides a ready-to-use ciphersuite using ML-KEM-768 (FIPS 203)
//! as a KEM and SHA-256 for hashing.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, Kem};

// Type aliases for the ML-KEM-768 encoded types
type EkEncoded = Encoded<ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>>;
type DkEncoded = Encoded<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>;
type CtEncoded = ml_kem::Ciphertext<MlKem768>;

/// ML-KEM-768 implemented as a KEM.
///
/// Uses ML-KEM-768 (FIPS 203) for key encapsulation. Unlike X25519-as-KEM,
/// ML-KEM is a true KEM with encapsulation and decapsulation operations
/// that are not based on Diffie-Hellman.
#[derive(Debug, Clone, Copy)]
pub struct MlKem768Kem;

/// ML-KEM-768 shared secret (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret([u8; 32]);

impl AsRef<[u8]> for MlKem768SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ML-KEM-768 decapsulation (private) key.
///
/// Stores the serialized key bytes to enable proper zeroization.
pub struct MlKem768DecapsulationKey {
    bytes: DkEncoded,
}

impl MlKem768DecapsulationKey {
    /// Create a new decapsulation key from raw bytes.
    ///
    /// Returns `None` if the byte slice is not exactly the correct length
    /// (2400 bytes for ML-KEM-768).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DkEncoded::default().len() {
            return None;
        }
        Some(Self {
            bytes: Array::from_fn(|i| bytes[i]),
        })
    }

    /// Generate a new random decapsulation key.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let (dk, _ek) = MlKem768::generate(rng);
        Self {
            bytes: dk.as_bytes(),
        }
    }

    /// Get the corresponding encapsulation (public) key.
    pub fn encapsulation_key(&self) -> MlKem768EncapsulationKey {
        let dk = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&self.bytes);
        let ek = dk.encapsulation_key();
        MlKem768EncapsulationKey(ek.as_bytes())
    }

    /// Reconstruct the inner ml-kem decapsulation key.
    fn to_inner(&self) -> ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params> {
        ml_kem::kem::DecapsulationKey::from_bytes(&self.bytes)
    }
}

impl Zeroize for MlKem768DecapsulationKey {
    fn zeroize(&mut self) {
        self.bytes.as_mut_slice().zeroize();
    }
}

impl Drop for MlKem768DecapsulationKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// ML-KEM-768 encapsulation (public) key (1184 bytes).
#[derive(Clone)]
pub struct MlKem768EncapsulationKey(EkEncoded);

impl MlKem768EncapsulationKey {
    /// Create from raw bytes.
    ///
    /// Returns `None` if the byte slice is not exactly the correct length
    /// (1184 bytes for ML-KEM-768).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != EkEncoded::default().len() {
            return None;
        }
        Some(Self(Array::from_fn(|i| bytes[i])))
    }

    /// Get the raw bytes.
    pub fn to_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Reconstruct the inner ml-kem encapsulation key.
    fn to_inner(&self) -> ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params> {
        ml_kem::kem::EncapsulationKey::from_bytes(&self.0)
    }
}

impl AsRef<[u8]> for MlKem768EncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Zeroize for MlKem768EncapsulationKey {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

/// ML-KEM-768 ciphertext (1088 bytes).
#[derive(Clone)]
pub struct MlKem768Ciphertext(CtEncoded);

impl MlKem768Ciphertext {
    /// Create from raw bytes.
    ///
    /// Returns `None` if the byte slice is not exactly the correct length
    /// (1088 bytes for ML-KEM-768).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CtEncoded::default().len() {
            return None;
        }
        Some(Self(Array::from_fn(|i| bytes[i])))
    }

    /// Get the raw bytes.
    pub fn to_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for MlKem768Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Zeroize for MlKem768Ciphertext {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

/// Error type for ML-KEM-768 KEM operations.
#[derive(Debug, Clone, Copy)]
pub struct MlKem768KemError;

impl core::fmt::Display for MlKem768KemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ML-KEM-768 KEM operation failed")
    }
}

impl Kem for MlKem768Kem {
    type EncapsulationKey = MlKem768EncapsulationKey;
    type DecapsulationKey = MlKem768DecapsulationKey;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = MlKem768SharedSecret;
    type Error = MlKem768KemError;

    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        let inner_ek = ek.to_inner();
        let (ct, ss) = inner_ek.encapsulate(rng).map_err(|_| MlKem768KemError)?;
        let mut ss_bytes = [0u8; 32];
        ss_bytes.copy_from_slice(ss.as_slice());
        Ok((MlKem768Ciphertext(ct), MlKem768SharedSecret(ss_bytes)))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let inner_dk = dk.to_inner();
        let ss = inner_dk.decapsulate(&ct.0).map_err(|_| MlKem768KemError)?;
        let mut ss_bytes = [0u8; 32];
        ss_bytes.copy_from_slice(ss.as_slice());
        Ok(MlKem768SharedSecret(ss_bytes))
    }
}

/// ML-KEM-768 + SHA-256 ciphersuite.
#[derive(Debug, Clone, Copy)]
pub struct MlKem768Sha256;

impl CipherSuite for MlKem768Sha256 {
    type Kem = MlKem768Kem;
    type Hash = sha2::Sha256;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let mut rng = rand::thread_rng();

        // Generate keypair
        let dk = MlKem768DecapsulationKey::generate(&mut rng);
        let ek = dk.encapsulation_key();

        // Encapsulate
        let (ct, ss1) = MlKem768Kem::encaps(&ek, &mut rng).unwrap();

        // Decapsulate
        let ss2 = MlKem768Kem::decaps(&dk, &ct).unwrap();

        // Shared secrets must match
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let mut rng = rand::thread_rng();

        let dk = MlKem768DecapsulationKey::generate(&mut rng);
        let ek = dk.encapsulation_key();

        // Serialize and deserialize encapsulation key
        let ek_bytes = ek.to_bytes();
        let ek2 = MlKem768EncapsulationKey::from_bytes(ek_bytes).unwrap();
        assert_eq!(ek.as_ref(), ek2.as_ref());

        // Encapsulate with deserialized key, decapsulate with original dk
        let (ct, ss1) = MlKem768Kem::encaps(&ek2, &mut rng).unwrap();
        let ss2 = MlKem768Kem::decaps(&dk, &ct).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_ciphertext_serialization_roundtrip() {
        let mut rng = rand::thread_rng();

        let dk = MlKem768DecapsulationKey::generate(&mut rng);
        let ek = dk.encapsulation_key();

        let (ct, ss1) = MlKem768Kem::encaps(&ek, &mut rng).unwrap();

        // Serialize and deserialize ciphertext
        let ct_bytes = ct.to_bytes();
        let ct2 = MlKem768Ciphertext::from_bytes(ct_bytes).unwrap();

        let ss2 = MlKem768Kem::decaps(&dk, &ct2).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_wrong_length_rejected() {
        assert!(MlKem768EncapsulationKey::from_bytes(&[0u8; 32]).is_none());
        assert!(MlKem768DecapsulationKey::from_bytes(&[0u8; 32]).is_none());
        assert!(MlKem768Ciphertext::from_bytes(&[0u8; 32]).is_none());
    }
}
