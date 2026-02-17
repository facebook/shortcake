// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Error types for the shortcake protocol.

use core::fmt;

/// Errors that can occur during protocol execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// KEM encapsulation failed.
    EncapsulationFailed,
    /// KEM decapsulation failed.
    DecapsulationFailed,
    /// Commitment verification failed.
    CommitmentMismatch,
    /// Reflection attack detected (encapsulation key equals ciphertext).
    ReflectionDetected,
    /// HKDF key derivation failed.
    KdfError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EncapsulationFailed => write!(f, "KEM encapsulation failed"),
            Error::DecapsulationFailed => write!(f, "KEM decapsulation failed"),
            Error::CommitmentMismatch => write!(f, "commitment verification failed"),
            Error::ReflectionDetected => write!(f, "reflection attack detected"),
            Error::KdfError => write!(f, "key derivation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
