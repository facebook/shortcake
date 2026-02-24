// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Protocol messages for the shortcake key exchange.

use core::fmt;
use core::marker::PhantomData;

use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use crate::ciphersuite::{CipherSuite, HashOutputLen, PublicKeyLen};
use crate::errors::ShortcakeError;

/// The first protocol message, sent from the initiator to the responder.
///
/// Contains the initiator's ephemeral public key and a commitment to the
/// public key and a secret nonce.
pub struct MessageOne<CS: CipherSuite> {
    /// The initiator's ephemeral public key.
    pub(crate) public_key: GenericArray<u8, PublicKeyLen<CS>>,
    /// Hash commitment to the initiator's public key and nonce.
    pub(crate) commitment: GenericArray<u8, HashOutputLen<CS>>,
}

impl<CS: CipherSuite> MessageOne<CS> {
    /// Returns the serialized size of this message in bytes.
    pub fn size() -> usize {
        PublicKeyLen::<CS>::USIZE + HashOutputLen::<CS>::USIZE
    }

    /// Returns the initiator's ephemeral public key.
    pub fn public_key(&self) -> &GenericArray<u8, PublicKeyLen<CS>> {
        &self.public_key
    }

    /// Returns the hash commitment.
    pub fn commitment(&self) -> &GenericArray<u8, HashOutputLen<CS>> {
        &self.commitment
    }

    /// Writes the serialized message into the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::Serialization`] if `buf.len() < Self::size()`.
    pub fn try_write_to(&self, buf: &mut [u8]) -> Result<(), ShortcakeError> {
        let pk_len = PublicKeyLen::<CS>::USIZE;
        if buf.len() < Self::size() {
            return Err(ShortcakeError::Serialization);
        }
        buf[..pk_len].copy_from_slice(&self.public_key);
        buf[pk_len..Self::size()].copy_from_slice(&self.commitment);
        Ok(())
    }

    /// Writes the serialized message into the provided buffer.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < Self::size()`.
    pub fn write_to(&self, buf: &mut [u8]) {
        self.try_write_to(buf).expect("buffer too small")
    }

    /// Serializes this message to a byte vector.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0u8; Self::size()];
        self.write_to(&mut bytes);
        bytes
    }

    /// Deserializes a message from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::Deserialization`] if the slice length does
    /// not match the expected message size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShortcakeError> {
        let pk_len = PublicKeyLen::<CS>::USIZE;
        if bytes.len() != Self::size() {
            return Err(ShortcakeError::Deserialization);
        }
        Ok(Self {
            public_key: GenericArray::clone_from_slice(&bytes[..pk_len]),
            commitment: GenericArray::clone_from_slice(&bytes[pk_len..]),
        })
    }
}

impl<CS: CipherSuite> Clone for MessageOne<CS> {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            commitment: self.commitment.clone(),
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for MessageOne<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageOne")
            .field("public_key", &self.public_key)
            .field("commitment", &self.commitment)
            .finish()
    }
}

impl<CS: CipherSuite> PartialEq for MessageOne<CS> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.commitment == other.commitment
    }
}

impl<CS: CipherSuite> Eq for MessageOne<CS> {}

/// The second protocol message, sent from the responder to the initiator.
///
/// Contains the responder's ephemeral public key and a random nonce.
pub struct MessageTwo<CS: CipherSuite> {
    /// The responder's ephemeral public key.
    pub(crate) public_key: GenericArray<u8, PublicKeyLen<CS>>,
    /// The responder's random nonce.
    pub(crate) nonce: GenericArray<u8, HashOutputLen<CS>>,
}

impl<CS: CipherSuite> MessageTwo<CS> {
    /// Returns the serialized size of this message in bytes.
    pub fn size() -> usize {
        PublicKeyLen::<CS>::USIZE + HashOutputLen::<CS>::USIZE
    }

    /// Returns the responder's ephemeral public key.
    pub fn public_key(&self) -> &GenericArray<u8, PublicKeyLen<CS>> {
        &self.public_key
    }

    /// Returns the responder's random nonce.
    pub fn nonce(&self) -> &GenericArray<u8, HashOutputLen<CS>> {
        &self.nonce
    }

    /// Writes the serialized message into the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::Serialization`] if `buf.len() < Self::size()`.
    pub fn try_write_to(&self, buf: &mut [u8]) -> Result<(), ShortcakeError> {
        let pk_len = PublicKeyLen::<CS>::USIZE;
        if buf.len() < Self::size() {
            return Err(ShortcakeError::Serialization);
        }
        buf[..pk_len].copy_from_slice(&self.public_key);
        buf[pk_len..Self::size()].copy_from_slice(&self.nonce);
        Ok(())
    }

    /// Writes the serialized message into the provided buffer.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < Self::size()`.
    pub fn write_to(&self, buf: &mut [u8]) {
        self.try_write_to(buf).expect("buffer too small")
    }

    /// Serializes this message to a byte vector.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0u8; Self::size()];
        self.write_to(&mut bytes);
        bytes
    }

    /// Deserializes a message from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::Deserialization`] if the slice length does
    /// not match the expected message size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShortcakeError> {
        let pk_len = PublicKeyLen::<CS>::USIZE;
        if bytes.len() != Self::size() {
            return Err(ShortcakeError::Deserialization);
        }
        Ok(Self {
            public_key: GenericArray::clone_from_slice(&bytes[..pk_len]),
            nonce: GenericArray::clone_from_slice(&bytes[pk_len..]),
        })
    }
}

impl<CS: CipherSuite> Clone for MessageTwo<CS> {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for MessageTwo<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageTwo")
            .field("public_key", &self.public_key)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl<CS: CipherSuite> PartialEq for MessageTwo<CS> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.nonce == other.nonce
    }
}

impl<CS: CipherSuite> Eq for MessageTwo<CS> {}

/// The third protocol message, sent from the initiator to the responder.
///
/// Contains the initiator's nonce, which allows the responder to open and
/// verify the commitment from [`MessageOne`].
pub struct MessageThree<CS: CipherSuite> {
    /// The initiator's random nonce.
    pub(crate) nonce: GenericArray<u8, HashOutputLen<CS>>,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> MessageThree<CS> {
    /// Creates a new [`MessageThree`] from a nonce.
    pub(crate) fn new(nonce: GenericArray<u8, HashOutputLen<CS>>) -> Self {
        Self {
            nonce,
            _marker: PhantomData,
        }
    }

    /// Returns the serialized size of this message in bytes.
    pub fn size() -> usize {
        HashOutputLen::<CS>::USIZE
    }

    /// Returns the initiator's nonce.
    pub fn nonce(&self) -> &GenericArray<u8, HashOutputLen<CS>> {
        &self.nonce
    }

    /// Writes the serialized message into the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::Serialization`] if `buf.len() < Self::size()`.
    pub fn try_write_to(&self, buf: &mut [u8]) -> Result<(), ShortcakeError> {
        if buf.len() < Self::size() {
            return Err(ShortcakeError::Serialization);
        }
        buf[..Self::size()].copy_from_slice(&self.nonce);
        Ok(())
    }

    /// Writes the serialized message into the provided buffer.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < Self::size()`.
    pub fn write_to(&self, buf: &mut [u8]) {
        self.try_write_to(buf).expect("buffer too small")
    }

    /// Serializes this message to a byte vector.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0u8; Self::size()];
        self.write_to(&mut bytes);
        bytes
    }

    /// Deserializes a message from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::Deserialization`] if the slice length does
    /// not match the expected message size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShortcakeError> {
        if bytes.len() != Self::size() {
            return Err(ShortcakeError::Deserialization);
        }
        Ok(Self::new(GenericArray::clone_from_slice(bytes)))
    }
}

impl<CS: CipherSuite> Clone for MessageThree<CS> {
    fn clone(&self) -> Self {
        Self::new(self.nonce.clone())
    }
}

impl<CS: CipherSuite> fmt::Debug for MessageThree<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageThree")
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl<CS: CipherSuite> PartialEq for MessageThree<CS> {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
    }
}

impl<CS: CipherSuite> Eq for MessageThree<CS> {}
