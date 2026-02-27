// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Deterministic test vectors for the Shortcake protocol.
//!
//! These vectors use a seeded ChaCha20 RNG to produce reproducible outputs.
//! If any protocol computation changes, these tests will fail.

#![cfg(feature = "x25519-sha256")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shortcake::{Initiator, Responder, X25519DecapsulationKey, X25519Sha256};

fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0u8; 32])
}

#[test]
fn test_vector_full_protocol() {
    let mut rng = seeded_rng();

    // Generate keypair
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();

    // Move 1
    let (initiator_state, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
    let msg1_ek = msg1.ek.to_bytes();
    let msg1_commitment: [u8; 32] = msg1.commitment.into();

    // Move 2
    let (responder_state, msg2) =
        Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
    let msg2_ct = msg2.ct.to_bytes();
    let msg2_nonce = msg2.responder_nonce;

    // Move 3
    let (initiator_confirm, msg3) = initiator_state
        .handle_responder_response(msg2.ct, msg2.responder_nonce)
        .unwrap();
    let msg3_nonce = msg3.initiator_nonce;

    // Verify commitment
    let responder_confirm = responder_state
        .handle_initiator_nonce(msg3.initiator_nonce)
        .unwrap();

    // SAS
    let sas = *initiator_confirm.sas().as_bytes();
    assert_eq!(
        initiator_confirm.sas().as_bytes(),
        responder_confirm.sas().as_bytes()
    );

    // Finalize
    let mut key = [0u8; 32];
    initiator_confirm
        .finalize(b"test-salt", b"test-info", &mut key)
        .unwrap();
    let mut key2 = [0u8; 32];
    responder_confirm
        .finalize(b"test-salt", b"test-info", &mut key2)
        .unwrap();
    assert_eq!(key, key2);

    // Assert against known test vectors
    assert_eq!(
        hex::encode(msg1_ek),
        "bc01d55dca171aea242e1a2d6be28a7975c46407331cd8478167138605122863"
    );
    assert_eq!(
        hex::encode(msg1_commitment),
        "252197cf14027303560bc3e5bd1a7995160c975bb8c96b46abdaf29ec4ed387c"
    );
    assert_eq!(
        hex::encode(msg2_ct),
        "1a081d02543c92bdfd979bae89395200cf08aa7dcb1d92bc29ac9fb2aa855d35"
    );
    assert_eq!(
        hex::encode(msg2_nonce),
        "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
    );
    assert_eq!(
        hex::encode(msg3_nonce),
        "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    );
    assert_eq!(
        hex::encode(sas),
        "9a62ec068c660631106c6fd2c0b366d59e41c669f1405d03ad1fef7153634244"
    );
    assert_eq!(
        hex::encode(key),
        "703387ceefaef3311d5e57cb1a9da7546f3fa43fe5d6184655f9c18facf5080e"
    );
}
