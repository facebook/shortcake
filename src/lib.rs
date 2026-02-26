// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! # Shortcake
//!
//! A generic, `#![no_std]`-compatible Rust implementation of the Pasini-Vaudenay
//! 3-move SAS-based authenticated key agreement protocol.
//!
//! ## Overview
//!
//! This crate implements a short authenticated strings (SAS) protocol for
//! establishing a shared secret between two parties (Initiator and Responder)
//! with human verification of a short code.
//!
//! ## Usage
//!
//! The protocol is generic over a [`CipherSuite`] that bundles a KEM and hash
//! function. Enable the `x25519-sha256` feature for a ready-to-use ciphersuite.

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
pub use sas::{Sas, SAS_LEN};

#[cfg(feature = "x25519-sha256")]
mod x25519;

#[cfg(feature = "x25519-sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519-sha256")))]
pub use x25519::{
    X25519Ciphertext, X25519DecapsulationKey, X25519EncapsulationKey, X25519Kem, X25519Sha256,
};

/// 32-byte nonce used in the protocol.
pub type Nonce = [u8; 32];
