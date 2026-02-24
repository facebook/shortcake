// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Cipher suite trait and default implementation.

use digest::{core_api::BlockSizeUser, Digest, OutputSizeUser};

use crate::key_exchange::KeyExchange;

/// A cipher suite grouping the cryptographic primitives used by the protocol.
///
/// A cipher suite pairs a [`KeyExchange`] algorithm with a hash function. The
/// hash function is used for commitment computation, SAS derivation, and
/// HKDF-based shared secret derivation.
///
/// # Example
///
/// ```rust
/// use shortcake::{CipherSuite, KeyExchange};
///
/// struct MyCipherSuite;
///
/// impl CipherSuite for MyCipherSuite {
///     type KeyExchange = shortcake::X25519;
///     type Hash = sha2::Sha256;
/// }
/// ```
pub trait CipherSuite {
    /// The key exchange algorithm.
    type KeyExchange: KeyExchange;

    /// The hash function used for commitments, SAS computation, and HKDF.
    ///
    /// Must implement [`Digest`], [`BlockSizeUser`] (required for HKDF via
    /// [`SimpleHmac`](hmac::SimpleHmac)), and [`Clone`].
    type Hash: Digest + BlockSizeUser + Clone;
}

/// The default cipher suite using X25519 key exchange and SHA-256.
///
/// This provides a 128-bit security level with a 40-bit SAS.
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type KeyExchange = crate::key_exchange::X25519;
    type Hash = sha2::Sha256;
}

// ---------------------------------------------------------------------------
// Internal type aliases for readability
// ---------------------------------------------------------------------------

/// The public key length for a given cipher suite.
pub(crate) type PublicKeyLen<CS> = <<CS as CipherSuite>::KeyExchange as KeyExchange>::PublicKeyLen;

/// The raw shared secret length for a given cipher suite.
pub(crate) type SharedSecretLen<CS> =
    <<CS as CipherSuite>::KeyExchange as KeyExchange>::SharedSecretLen;

/// The hash output length for a given cipher suite.
pub(crate) type HashOutputLen<CS> = <<CS as CipherSuite>::Hash as OutputSizeUser>::OutputSize;

/// The secret key type for a given cipher suite.
pub(crate) type KxSecretKey<CS> = <<CS as CipherSuite>::KeyExchange as KeyExchange>::SecretKey;
