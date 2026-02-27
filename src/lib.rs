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
//! for a full working example with serialization.
//!
//! # Protocol Execution
//!
//! The protocol is a 3-move exchange. Each state transition consumes the
//! previous state, making it impossible to reuse or skip steps. Fallible
//! steps return [`Error`] on failure (e.g., commitment mismatch,
//! reflection attack detected, decapsulation failure).
//!
//! ## Initiator: Generate Keypair and Start (Move 1)
//!
//! The Initiator generates a KEM keypair and starts the protocol. This
//! produces an [`InitiatorFirstMessage`] (containing an encapsulation key
//! and a commitment) to send to the Responder, and an
//! [`InitiatorAwaitingResponse`] state to retain locally.
//!
//! ```ignore
//! use rand::rngs::OsRng;
//! use shortcake::{Initiator, X25519DecapsulationKey, X25519Sha256};
//!
//! let mut rng = OsRng;
//!
//! let dk = X25519DecapsulationKey::generate(&mut rng);
//! let ek = dk.encapsulation_key();
//!
//! let (initiator_state, msg1) =
//!     Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
//!
//! // Serialize msg1 for transmission:
//! let ek_bytes = msg1.ek.to_bytes();                    // [u8; 32]
//! let commitment_bytes: [u8; 32] = msg1.commitment.into(); // [u8; 32]
//! // Send ek_bytes and commitment_bytes to the Responder.
//! ```
//!
//! ## Responder: Receive Move 1, Send Move 2
//!
//! The Responder deserializes the first message, encapsulates to the
//! Initiator's public key, and generates a nonce. This produces a
//! [`ResponderResponse`] (containing a ciphertext and nonce) to send back,
//! and a [`ResponderAwaitingNonce`] state to retain locally.
//!
//! ```ignore
//! use shortcake::{Responder, X25519EncapsulationKey, X25519Sha256};
//!
//! // Deserialize msg1 received from the Initiator:
//! let ek = X25519EncapsulationKey::from_bytes(ek_bytes);
//! let commitment = commitment_bytes.into();
//!
//! let (responder_state, msg2) =
//!     Responder::<X25519Sha256>::start(&mut rng, ek, commitment)?;
//!
//! // Serialize msg2 for transmission:
//! let ct_bytes = msg2.ct.to_bytes();              // [u8; 32]
//! let responder_nonce = msg2.responder_nonce;      // [u8; 32]
//! // Send ct_bytes and responder_nonce to the Initiator.
//! ```
//!
//! ## Initiator: Receive Move 2, Send Move 3
//!
//! The Initiator deserializes the response, decapsulates the ciphertext,
//! and reveals its nonce. This produces an [`InitiatorThirdMessage`]
//! (containing the initiator nonce) to send back, and an
//! [`InitiatorAwaitingSasConfirmation`] state.
//!
//! ```ignore
//! use shortcake::X25519Ciphertext;
//!
//! // Deserialize msg2 received from the Responder:
//! let ct = X25519Ciphertext::from_bytes(ct_bytes);
//!
//! let (initiator_confirm, msg3) = initiator_state
//!     .handle_responder_response(ct, responder_nonce)?;
//!
//! // Serialize msg3 for transmission:
//! let initiator_nonce = msg3.initiator_nonce;      // [u8; 32]
//! // Send initiator_nonce to the Responder.
//! ```
//!
//! ## Responder: Receive Move 3, Verify Commitment
//!
//! The Responder uses the revealed nonce to verify the Initiator's
//! commitment from Move 1. If verification succeeds, the Responder
//! transitions to [`ResponderAwaitingSasConfirmation`].
//!
//! ```ignore
//! let responder_confirm = responder_state
//!     .handle_initiator_nonce(initiator_nonce)?;
//! ```
//!
//! ## SAS Comparison
//!
//! Both sides now hold a [`Sas`] value. The library returns the full
//! [`SAS_MAX_LEN`]-byte SAS; callers should truncate to a prefix of the
//! desired length for display. [`DEFAULT_SAS_LEN`] (5 bytes / 40 bits) is
//! a reasonable default.
//!
//! The two parties compare their SAS values out-of-band (e.g., reading
//! digits aloud, displaying an emoji sequence). If they do **not** match,
//! the protocol must be aborted.
//!
//! ```ignore
//! use shortcake::DEFAULT_SAS_LEN;
//!
//! let i_sas = &initiator_confirm.sas().as_bytes()[..DEFAULT_SAS_LEN];
//! let r_sas = &responder_confirm.sas().as_bytes()[..DEFAULT_SAS_LEN];
//! assert_eq!(i_sas, r_sas);
//! ```
//!
//! ## Key Derivation
//!
//! After the human confirms the SAS values match, both sides call
//! [`finalize()`](InitiatorAwaitingSasConfirmation::finalize) with the same
//! `salt` and `info` to derive a shared key via HKDF.
//!
//! ```ignore
//! let mut initiator_key = [0u8; 32];
//! let mut responder_key = [0u8; 32];
//!
//! initiator_confirm.finalize(b"my-salt", b"my-info", &mut initiator_key)?;
//! responder_confirm.finalize(b"my-salt", b"my-info", &mut responder_key)?;
//!
//! assert_eq!(initiator_key, responder_key);
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
mod kdf;
mod responder;
mod sas;

pub use ciphersuite::{CipherSuite, Kem};
pub use error::Error;
pub use initiator::{
    Initiator, InitiatorAwaitingResponse, InitiatorAwaitingSasConfirmation, InitiatorFirstMessage,
    InitiatorThirdMessage,
};
pub use responder::{
    Responder, ResponderAwaitingNonce, ResponderAwaitingSasConfirmation, ResponderResponse,
};
pub use sas::{Sas, DEFAULT_SAS_LEN, SAS_MAX_LEN};

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
