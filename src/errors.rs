// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Error types for the shortcake protocol.

/// The error type for the shortcake protocol.
#[derive(Debug, thiserror::Error)]
pub enum ShortcakeError {
    /// The commitment verification failed. This indicates that the initiator's
    /// public key or nonce was tampered with, or that a man-in-the-middle
    /// attack may have occurred.
    #[error("commitment verification failed")]
    InvalidCommitment,

    /// The received public key is invalid (e.g., all zeros or identical to
    /// the local public key).
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Deserialization failed due to invalid input length.
    #[error("deserialization failed: invalid length")]
    Deserialization,

    /// Serialization failed due to an output buffer that was too small.
    #[error("serialization failed: buffer too small")]
    Serialization,
}
