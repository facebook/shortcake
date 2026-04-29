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
//! function. Enable the `xwing` feature for a ready-to-use ciphersuite using
//! the X-Wing hybrid KEM (X25519 + ML-KEM-768) and SHA3-256:
//!
//! ```toml
//! [dependencies]
//! shortcake = { version = "0.1.0-pre.3", features = ["xwing"] }
//! ```
//!
//! We will use [`XWingSha3`] in the examples below.
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
//! use shortcake::{Initiator, XWingSha3};
//!
//! let mut rng = /* your CryptoRng */;
//! let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
//! // Send msg1 to the Responder.
//! ```
//!
//! ## Move 2: Responder processes Move 1
//!
//! The Responder encapsulates to the Initiator's public key, generates a
//! nonce, and produces a [`MessageTwo`] to send back.
//!
//! ```ignore
//! use shortcake::{Responder, XWingSha3};
//!
//! let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1)
//!     .expect("Responder failed to start");
//! // Send msg2 to the Initiator.
//! ```
//!
//! ## Move 3: Initiator processes Move 2
//!
//! The Initiator decapsulates the ciphertext, computes the SAS, and
//! produces a [`MessageThree`] to send back along with a [`ProtocolOutput`].
//!
//! ```ignore
//! let (i_output, msg3) = initiator.finish(msg2)
//!     .expect("Initiator failed to finish");
//! // Send msg3 to the Responder.
//! ```
//!
//! ## Responder processes Move 3
//!
//! The Responder verifies the commitment and computes its own [`ProtocolOutput`].
//!
//! ```ignore
//! let r_output = responder.finish(msg3)
//!     .expect("Responder failed to finish");
//! ```
//!
//! ## Verification
//!
//! Both parties compare their SAS codes out-of-band (e.g., reading
//! digits aloud, displaying an emoji sequence). Once confirmed, call
//! `into_session_key()` to obtain the session key.
//!
//! ```ignore
//! // Compare SAS codes out-of-band
//! assert_eq!(i_output.sas_code(), r_output.sas_code());
//!
//! // After human confirmation, extract the session key
//! let i_key = i_output.into_session_key();
//! let r_key = r_output.into_session_key();
//! ```
//!
//! # Features
//!
//! - `xwing` — Ready-to-use ciphersuite using X-Wing (X25519 + ML-KEM-768)
//!   and SHA3-256, providing both classical and post-quantum security.
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
#[cfg(feature = "getrandom")]
pub use getrandom;
pub use initiator::{Initiator, MessageOne, MessageThree};
pub use rand_core;
pub use responder::{MessageTwo, Responder};
pub use verification::ProtocolOutput;

#[cfg(feature = "xwing")]
mod xwing;

#[cfg(feature = "xwing")]
#[cfg_attr(docsrs, doc(cfg(feature = "xwing")))]
pub use xwing::{
    XWingCiphertext, XWingDecapsulationKey, XWingEncapsulationKey, XWingKem, XWingKemError,
    XWingSha3, XWingSharedSecret,
};

/// 32-byte nonce used in the protocol.
pub type Nonce = [u8; 32];
