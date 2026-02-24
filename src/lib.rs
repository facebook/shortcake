// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! # shortcake
//!
//! A SAS-based (Short Authentication String) authenticated key exchange
//! protocol.
//!
//! **Warning: This crate has not been audited. Use at your own risk.**
//!
//! # Overview
//!
//! `shortcake` (**SHORT** **C**ode **A**uthenticated **K**ey **E**xchange)
//! implements a 3-message authenticated key exchange protocol based on
//! the Pasini-Vaudenay (2006) message cross-authentication scheme. The
//! protocol allows two parties to establish a shared secret over an untrusted
//! channel, with authentication provided by a short authentication string
//! (SAS) that users verify out-of-band.
//!
//! The protocol is provably secure in the random oracle model against
//! man-in-the-middle attacks, under the assumption that the SAS verification
//! is performed faithfully by the user.
//!
//! # Cipher Suites
//!
//! The protocol is generic over a [`CipherSuite`] that groups a
//! [`KeyExchange`] algorithm and a hash function. The default cipher suite
//! ([`DefaultCipherSuite`]) uses X25519 and SHA-256.
//!
//! Custom cipher suites can be defined by implementing the [`CipherSuite`]
//! and [`KeyExchange`] traits.
//!
//! # Protocol
//!
//! The protocol consists of three messages exchanged between an [`Initiator`]
//! and a [`Responder`]:
//!
//! 1. **Initiator → Responder** ([`MessageOne`]): The initiator generates an
//!    ephemeral key pair and a random nonce, then sends its public key along
//!    with a hash commitment to the public key and nonce.
//!
//! 2. **Responder → Initiator** ([`MessageTwo`]): The responder generates its
//!    own ephemeral key pair and a random nonce, then sends its public key
//!    and nonce.
//!
//! 3. **Initiator → Responder** ([`MessageThree`]): The initiator reveals its
//!    nonce, allowing the responder to open and verify the commitment from
//!    step 1.
//!
//! After the exchange, both parties independently compute a short
//! authentication string (SAS). The users verify out-of-band that the SAS
//! values match, confirming that no man-in-the-middle attack has occurred.
//! Upon successful verification, both parties derive the same shared secret
//! via ECDH and HKDF.
//!
//! # Usage
//!
//! ```rust
//! # use shortcake::{DefaultCipherSuite, Initiator, Responder};
//! # use rand::rngs::OsRng;
//! #
//! let mut rng = OsRng;
//!
//! // Step 1: Initiator starts the protocol
//! let (msg1, initiator) = Initiator::<DefaultCipherSuite>::start(&mut rng);
//!
//! // Step 2: Responder processes MessageOne and responds
//! let (msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();
//!
//! // Step 3: Initiator processes MessageTwo and produces MessageThree
//! let (msg3, initiator_output) = initiator.finish(&msg2).unwrap();
//!
//! // Step 4: Responder processes MessageThree
//! let responder_output = responder.finish(&msg3).unwrap();
//!
//! // Both parties now have the same SAS and shared secret
//! assert_eq!(initiator_output.sas, responder_output.sas);
//! assert_eq!(initiator_output.shared_secret, responder_output.shared_secret);
//!
//! // Users verify the SAS out-of-band (e.g., by comparing displayed codes).
//! // Only use the shared secret after successful SAS verification!
//! ```
//!
//! # Serialization
//!
//! All protocol messages support conversion to and from bytes via
//! [`to_bytes()`](MessageOne::to_bytes) and
//! [`from_bytes()`](MessageOne::from_bytes) methods, suitable for
//! transmission over any transport.
//!
//! # References
//!
//! - S. Pasini and S. Vaudenay, "An Optimal Non-Interactive Message
//!   Authentication Protocol," CT-RSA 2006.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(test), deny(unsafe_code))]
#![warn(clippy::doc_markdown, missing_docs, rustdoc::all)]

mod ciphersuite;
mod errors;
mod key_exchange;
mod messages;
mod protocol;

#[cfg(test)]
mod tests;

pub use ciphersuite::{CipherSuite, DefaultCipherSuite};
pub use errors::ShortcakeError;
pub use key_exchange::{KeyExchange, X25519};
pub use messages::{MessageOne, MessageThree, MessageTwo};
pub use protocol::{Initiator, Output, Responder, SAS_LENGTH};

/// Re-export of `generic_array` for use in custom cipher suite implementations.
pub use generic_array;

/// Re-export of `rand_core` for convenience.
pub use rand_core;
