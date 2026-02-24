// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Key exchange trait and implementations.

use generic_array::{typenum::U32, ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::errors::ShortcakeError;

/// A trait for key exchange algorithms.
///
/// Implementations provide ephemeral key pair generation, public key
/// derivation, and Diffie-Hellman shared secret computation.
pub trait KeyExchange {
    /// The length of a serialized public key in bytes.
    type PublicKeyLen: ArrayLength<u8>;

    /// The length of the raw shared secret in bytes.
    type SharedSecretLen: ArrayLength<u8>;

    /// The secret key type.
    ///
    /// This type is intentionally opaque to prevent misuse of secret key
    /// material. It is consumed by [`diffie_hellman`](KeyExchange::diffie_hellman)
    /// to prevent reuse.
    type SecretKey;

    /// Generates a new ephemeral key pair.
    ///
    /// Returns the secret key and the serialized public key.
    fn generate_keypair(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (Self::SecretKey, GenericArray<u8, Self::PublicKeyLen>);

    /// Derives the serialized public key from a secret key reference.
    fn public_key(sk: &Self::SecretKey) -> GenericArray<u8, Self::PublicKeyLen>;

    /// Computes the Diffie-Hellman shared secret.
    ///
    /// The secret key is consumed to prevent reuse.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::InvalidPublicKey`] if the computed shared
    /// secret is degenerate (e.g., all zeros for X25519, indicating a
    /// low-order point).
    fn diffie_hellman(
        sk: Self::SecretKey,
        pk: &GenericArray<u8, Self::PublicKeyLen>,
    ) -> Result<GenericArray<u8, Self::SharedSecretLen>, ShortcakeError>;

    /// Validates that a received public key is well-formed.
    ///
    /// This performs primitive-level validation only (e.g., rejecting the
    /// identity point). Protocol-level checks such as rejecting reflected
    /// keys are handled separately.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::InvalidPublicKey`] if the key is invalid.
    fn validate_public_key(pk: &GenericArray<u8, Self::PublicKeyLen>)
        -> Result<(), ShortcakeError>;
}

/// X25519 Diffie-Hellman key exchange.
pub struct X25519;

impl KeyExchange for X25519 {
    type PublicKeyLen = U32;
    type SharedSecretLen = U32;
    type SecretKey = x25519_dalek::EphemeralSecret;

    fn generate_keypair(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (Self::SecretKey, GenericArray<u8, Self::PublicKeyLen>) {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        (secret, GenericArray::clone_from_slice(public.as_bytes()))
    }

    fn public_key(sk: &Self::SecretKey) -> GenericArray<u8, Self::PublicKeyLen> {
        let pk = x25519_dalek::PublicKey::from(sk);
        GenericArray::clone_from_slice(pk.as_bytes())
    }

    fn diffie_hellman(
        sk: Self::SecretKey,
        pk: &GenericArray<u8, Self::PublicKeyLen>,
    ) -> Result<GenericArray<u8, Self::SharedSecretLen>, ShortcakeError> {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(pk.as_slice());
        let their_pk = x25519_dalek::PublicKey::from(pk_bytes);
        let shared = sk.diffie_hellman(&their_pk);

        if shared.as_bytes().ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return Err(ShortcakeError::InvalidPublicKey);
        }

        Ok(GenericArray::clone_from_slice(shared.as_bytes()))
    }

    fn validate_public_key(
        pk: &GenericArray<u8, Self::PublicKeyLen>,
    ) -> Result<(), ShortcakeError> {
        if pk.as_slice().ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return Err(ShortcakeError::InvalidPublicKey);
        }
        Ok(())
    }
}
