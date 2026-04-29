// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Session key derivation.

use digest::{Digest, Output};

use crate::Nonce;

const SESSION_KEY_DOMAIN_SEPARATOR: &[u8] = b"shortcake-session-key-v1";

/// Derive a session key from the full protocol transcript.
pub fn derive_session_key<H: Digest>(
    kem_ss: &[u8],
    ek_bytes: &[u8],
    ct_bytes: &[u8],
    initiator_nonce: &Nonce,
    responder_nonce: &Nonce,
) -> Output<H> {
    let mut hasher = H::new();
    hasher.update(SESSION_KEY_DOMAIN_SEPARATOR);
    hasher.update((kem_ss.len() as u64).to_be_bytes());
    hasher.update(kem_ss);
    hasher.update((ek_bytes.len() as u64).to_be_bytes());
    hasher.update(ek_bytes);
    hasher.update((ct_bytes.len() as u64).to_be_bytes());
    hasher.update(ct_bytes);
    hasher.update(initiator_nonce);
    hasher.update(responder_nonce);
    hasher.finalize()
}
