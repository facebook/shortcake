// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! X-Wing + SHA3-256 ciphersuite implementation.
//!
//! This module provides a ready-to-use ciphersuite using X-Wing (a hybrid
//! KEM combining X25519 and ML-KEM-768) and SHA3-256 for hashing.

use rand_core::CryptoRng;
use core::mem::ManuallyDrop;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, Kem};

/// Size of the X-Wing encapsulation (public) key in bytes.
pub const ENCAPSULATION_KEY_SIZE: usize = x_wing::ENCAPSULATION_KEY_SIZE;

/// Size of the X-Wing ciphertext in bytes.
pub const CIPHERTEXT_SIZE: usize = x_wing::CIPHERTEXT_SIZE;

/// X-Wing implemented as a KEM.
///
/// X-Wing is a hybrid KEM combining X25519 and ML-KEM-768, providing
/// both classical and post-quantum security. The shared secret is derived
/// via SHA3-256 over the component shared secrets.
#[derive(Debug, Clone, Copy)]
pub struct XWingKem;

/// X-Wing shared secret (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct XWingSharedSecret([u8; 32]);

impl AsRef<[u8]> for XWingSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// X-Wing decapsulation (private) key.
///
/// Stores the fully expanded X-Wing key (ML-KEM-768 + X25519 key material)
/// so that decapsulation does not need to re-derive from the seed.
pub struct XWingDecapsulationKey {
    inner: ManuallyDrop<x_wing::DecapsulationKey>,
}

impl Drop for XWingDecapsulationKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for XWingDecapsulationKey {
    fn zeroize(&mut self) {
        // SAFETY: We zero the entire x-wing DecapsulationKey including all
        // expanded key material. ManuallyDrop prevents the inner Drop from
        // running on the zeroed memory.
        unsafe {
            core::ptr::write_bytes(
                &mut *self.inner as *mut x_wing::DecapsulationKey as *mut u8,
                0,
                core::mem::size_of::<x_wing::DecapsulationKey>(),
            );
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for XWingDecapsulationKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.inner.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for XWingDecapsulationKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DkVisitor;
        impl<'de> serde::de::Visitor<'de> for DkVisitor {
            type Value = XWingDecapsulationKey;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "32 bytes for X-Wing decapsulation key seed")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                let seed: [u8; 32] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;
                Ok(XWingDecapsulationKey::from_seed(seed))
            }
        }
        deserializer.deserialize_bytes(DkVisitor)
    }
}

impl XWingDecapsulationKey {
    /// Create a new decapsulation key from a 32-byte seed.
    ///
    /// The seed is expanded into the full X-Wing key material (ML-KEM-768
    /// decapsulation key + X25519 secret key) via SHAKE-256.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        use x_wing::KeyInit as _;
        Self {
            inner: ManuallyDrop::new(x_wing::DecapsulationKey::new(&seed.into())),
        }
    }

    /// Get the corresponding encapsulation (public) key.
    pub fn encapsulation_key(&self) -> XWingEncapsulationKey {
        use x_wing::{Decapsulator as _, KeyExport as _};

        let inner_ek = self.inner.encapsulation_key();
        let ek_bytes = inner_ek.to_bytes();
        let mut bytes = [0u8; ENCAPSULATION_KEY_SIZE];
        bytes.copy_from_slice(ek_bytes.as_slice());
        XWingEncapsulationKey(bytes)
    }
}

/// X-Wing encapsulation (public) key (1216 bytes).
#[derive(Clone)]
pub struct XWingEncapsulationKey([u8; ENCAPSULATION_KEY_SIZE]);

#[cfg(feature = "serde")]
impl serde::Serialize for XWingEncapsulationKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for XWingEncapsulationKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EkVisitor;
        impl<'de> serde::de::Visitor<'de> for EkVisitor {
            type Value = XWingEncapsulationKey;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    "{} bytes for X-Wing encapsulation key",
                    ENCAPSULATION_KEY_SIZE
                )
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                XWingEncapsulationKey::from_bytes(v)
                    .ok_or_else(|| E::invalid_length(v.len(), &self))
            }
        }
        deserializer.deserialize_bytes(EkVisitor)
    }
}

impl XWingEncapsulationKey {
    /// Create from raw bytes.
    ///
    /// Returns `None` if the byte slice is not exactly the correct length
    /// (1216 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ENCAPSULATION_KEY_SIZE {
            return None;
        }
        let mut arr = [0u8; ENCAPSULATION_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for XWingEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for XWingEncapsulationKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// X-Wing ciphertext (1120 bytes).
#[derive(Clone)]
pub struct XWingCiphertext([u8; CIPHERTEXT_SIZE]);

#[cfg(feature = "serde")]
impl serde::Serialize for XWingCiphertext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for XWingCiphertext {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CtVisitor;
        impl<'de> serde::de::Visitor<'de> for CtVisitor {
            type Value = XWingCiphertext;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{} bytes for X-Wing ciphertext", CIPHERTEXT_SIZE)
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                XWingCiphertext::from_bytes(v).ok_or_else(|| E::invalid_length(v.len(), &self))
            }
        }
        deserializer.deserialize_bytes(CtVisitor)
    }
}

impl XWingCiphertext {
    /// Create from raw bytes.
    ///
    /// Returns `None` if the byte slice is not exactly the correct length
    /// (1120 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CIPHERTEXT_SIZE {
            return None;
        }
        let mut arr = [0u8; CIPHERTEXT_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for XWingCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for XWingCiphertext {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Error type for X-Wing KEM operations.
#[derive(Debug, Clone, Copy)]
pub struct XWingKemError;

impl core::fmt::Display for XWingKemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "X-Wing KEM operation failed")
    }
}

impl Kem for XWingKem {
    type EncapsulationKey = XWingEncapsulationKey;
    type DecapsulationKey = XWingDecapsulationKey;
    type Ciphertext = XWingCiphertext;
    type SharedSecret = XWingSharedSecret;
    type Error = XWingKemError;

    fn generate(rng: &mut impl CryptoRng) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        use x_wing::{Decapsulator as _, KeyExport as _};

        let dk = <x_wing::DecapsulationKey as x_wing::Generate>::generate_from_rng(rng);
        let inner_ek = dk.encapsulation_key();
        let ek_bytes = inner_ek.to_bytes();

        let mut ek_arr = [0u8; ENCAPSULATION_KEY_SIZE];
        ek_arr.copy_from_slice(ek_bytes.as_slice());

        (
            XWingDecapsulationKey {
                inner: ManuallyDrop::new(dk),
            },
            XWingEncapsulationKey(ek_arr),
        )
    }

    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        use x_wing::Encapsulate as _;

        let inner_ek =
            x_wing::EncapsulationKey::try_from(ek.0.as_slice()).map_err(|_| XWingKemError)?;
        let (ct, ss) = inner_ek.encapsulate_with_rng(rng);

        let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
        ct_bytes.copy_from_slice(ct.as_slice());

        let mut ss_bytes = [0u8; 32];
        ss_bytes.copy_from_slice(ss.as_slice());

        Ok((XWingCiphertext(ct_bytes), XWingSharedSecret(ss_bytes)))
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        use x_wing::Decapsulate as _;

        let mut inner_ct = x_wing::Ciphertext::default();
        inner_ct.copy_from_slice(&ct.0);
        let ss = dk.inner.decapsulate(&inner_ct);

        let mut ss_bytes = [0u8; 32];
        ss_bytes.copy_from_slice(ss.as_slice());

        Ok(XWingSharedSecret(ss_bytes))
    }
}

/// X-Wing + SHA3-256 ciphersuite.
#[derive(Debug, Clone, Copy)]
pub struct XWingSha3;

impl CipherSuite for XWingSha3 {
    type Kem = XWingKem;
    type Hash = sha3::Sha3_256;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::UnwrapErr;

    fn test_rng() -> UnwrapErr<getrandom::SysRng> {
        UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn test_kem_roundtrip() {
        let mut rng = test_rng();

        // Generate keypair
        let (dk, ek) = XWingKem::generate(&mut rng);

        // Encapsulate
        let (ct, ss1) = XWingKem::encaps(&ek, &mut rng).unwrap();

        // Decapsulate
        let ss2 = XWingKem::decaps(&dk, &ct).unwrap();

        // Shared secrets must match
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let mut rng = test_rng();

        let (dk, ek) = XWingKem::generate(&mut rng);

        // Serialize and deserialize encapsulation key
        let ek_bytes = ek.as_bytes();
        let ek2 = XWingEncapsulationKey::from_bytes(ek_bytes).unwrap();
        assert_eq!(ek.as_ref(), ek2.as_ref());

        // Encapsulate with deserialized key, decapsulate with original dk
        let (ct, ss1) = XWingKem::encaps(&ek2, &mut rng).unwrap();
        let ss2 = XWingKem::decaps(&dk, &ct).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_ciphertext_serialization_roundtrip() {
        let mut rng = test_rng();

        let (dk, ek) = XWingKem::generate(&mut rng);

        let (ct, ss1) = XWingKem::encaps(&ek, &mut rng).unwrap();

        // Serialize and deserialize ciphertext
        let ct_bytes = ct.as_bytes();
        let ct2 = XWingCiphertext::from_bytes(ct_bytes).unwrap();

        let ss2 = XWingKem::decaps(&dk, &ct2).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_wrong_length_rejected() {
        assert!(XWingEncapsulationKey::from_bytes(&[0u8; 32]).is_none());
        assert!(XWingCiphertext::from_bytes(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_dk_from_seed_deterministic() {
        let seed = [42u8; 32];
        let dk1 = XWingDecapsulationKey::from_seed(seed);
        let dk2 = XWingDecapsulationKey::from_seed(seed);
        assert_eq!(
            dk1.encapsulation_key().as_ref(),
            dk2.encapsulation_key().as_ref()
        );
    }
}
