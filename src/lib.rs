// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! # Shortcake
//!
//! A generic, `#![no_std]`-compatible Rust implementation of the Pasini-Vaudenay
//! 3-move SAS-based authenticated key agreement protocol.
//!
//! # Overview
//!
//! Shortcake is a protocol between two parties — an Initiator and a
//! Responder — for establishing a shared secret with human verification of
//! a short code (the SAS). After exchanging three protocol messages, both
//! sides compare a Short Authentication String out-of-band (e.g., by reading
//! digits aloud). If the strings match, each side derives the same shared
//! key.
//!
//! # Setup
//!
//! The protocol is generic over a [`CipherSuite`] that bundles a KEM and hash
//! function. Enable the `x25519-sha256` or `mlkem768-sha256` feature for a
//! ready-to-use ciphersuite:
//!
//! ```toml
//! [dependencies]
//! shortcake = { version = "0.1", features = ["x25519-sha256"] }
//! ```
//!
//! We will use [`X25519Sha256`] in the examples below.
//!
//! See [`examples/protocol.rs`](https://github.com/facebook/shortcake/blob/main/examples/protocol.rs)
//! for a full working example.
//!
//! # Protocol Execution
//!
//! The protocol is a 3-move exchange. Each state transition consumes the
//! previous state, making it impossible to reuse or skip steps. Fallible
//! steps return [`Error`] on failure (e.g., commitment mismatch,
//! reflection attack detected, decapsulation failure).
//!
//! ## Move 1: Initiator starts
//!
//! The Initiator generates a KEM keypair internally, creates a commitment,
//! and produces a [`MessageOne`] to send to the Responder.
//!
//! ```ignore
//! use rand::rngs::OsRng;
//! use shortcake::{Initiator, X25519Sha256};
//!
//! let mut rng = OsRng;
//! let (initiator, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
//! // Send msg1 to the Responder.
//! ```
//!
//! ## Move 2: Responder processes Move 1
//!
//! The Responder encapsulates to the Initiator's public key, generates a
//! nonce, and produces a [`MessageTwo`] to send back.
//!
//! ```ignore
//! use shortcake::{Responder, X25519Sha256};
//!
//! let (responder, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1)
//!     .expect("Responder failed to start");
//! // Send msg2 to the Initiator.
//! ```
//!
//! ## Move 3: Initiator processes Move 2
//!
//! The Initiator decapsulates the ciphertext, computes the SAS, and
//! produces a [`MessageThree`] to send back along with a [`VerificationCode`].
//!
//! ```ignore
//! let (i_code, msg3) = initiator.finish(msg2)
//!     .expect("Initiator failed to finish");
//! // Send msg3 to the Responder.
//! ```
//!
//! ## Responder processes Move 3
//!
//! The Responder verifies the commitment and computes its own [`VerificationCode`].
//!
//! ```ignore
//! let r_code = responder.finish(msg3)
//!     .expect("Responder failed to finish");
//! ```
//!
//! ## Verification
//!
//! Both parties compare their verification codes out-of-band (e.g., reading
//! digits aloud, displaying an emoji sequence). If they match, call
//! [`VerificationCode::verify`] with the other party's code bytes to obtain
//! the shared secret.
//!
//! ```ignore
//! let r_code_bytes = r_code.as_bytes().to_vec();
//! let shared_secret = i_code.verify(&r_code_bytes)
//!     .expect("Verification failed");
//! ```
//!
//! # Features
//!
//! - `x25519-sha256` — Ready-to-use ciphersuite using X25519 and SHA-256.
//! - `mlkem768-sha256` — Post-quantum ciphersuite using ML-KEM-768 (FIPS 203)
//!   and SHA-256.
//! - `std` — Enable `std::error::Error` impl for the error type (disabled
//!   by default for `no_std`).

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod ciphersuite;
mod commitment;
mod error;
mod initiator;
mod responder;
mod sas;
mod verification;

pub use ciphersuite::{CipherSuite, Kem};
pub use error::Error;
pub use initiator::{Initiator, MessageOne, MessageThree};
pub use responder::{MessageTwo, Responder};
pub use verification::VerificationCode;

#[cfg(feature = "x25519-sha256")]
mod x25519;

#[cfg(feature = "x25519-sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519-sha256")))]
pub use x25519::{
    X25519Ciphertext, X25519DecapsulationKey, X25519EncapsulationKey, X25519Kem, X25519Sha256,
};

#[cfg(feature = "mlkem768-sha256")]
mod mlkem;

#[cfg(feature = "mlkem768-sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "mlkem768-sha256")))]
pub use mlkem::{
    MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey, MlKem768Kem,
    MlKem768Sha256,
};

/// 32-byte nonce used in the protocol.
pub type Nonce = [u8; 32];
