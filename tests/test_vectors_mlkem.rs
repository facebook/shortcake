// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Deterministic test vectors for the Shortcake protocol with ML-KEM-768.
//!
//! These vectors use a seeded ChaCha20 RNG to produce reproducible outputs.
//! If any protocol computation changes, these tests will fail.

#![cfg(feature = "mlkem768-sha256")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shortcake::{Initiator, MlKem768DecapsulationKey, MlKem768Sha256, Responder};

fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0u8; 32])
}

#[test]
fn test_vector_full_protocol_mlkem() {
    let mut rng = seeded_rng();

    // Generate keypair
    let dk = MlKem768DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();

    // Move 1
    let (initiator_state, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng, ek, dk);
    let msg1_commitment: [u8; 32] = msg1.commitment.into();

    // Move 2
    let (responder_state, msg2) =
        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
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

    // Assert against known test vectors.
    // ML-KEM encapsulation keys (1184 bytes) and ciphertexts (1088 bytes) are
    // large, so we verify the protocol-level values that transitively depend on
    // the full KEM output: commitment, nonces, SAS, and derived key.
    assert_eq!(
        hex::encode(msg1_commitment),
        "ad797a77dbba97b055bb28927c5da5ec1a8356065d994615c135beb6cee7683c"
    );
    assert_eq!(
        hex::encode(msg2_nonce),
        "2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d"
    );
    assert_eq!(
        hex::encode(msg3_nonce),
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
    );
    assert_eq!(
        hex::encode(sas),
        "d64c9b1747556b65759f6e81f8e647e67c7aa1ad7a44b52592350a7ec7616e73"
    );
    assert_eq!(
        hex::encode(key),
        "30bef035a4ae4ff56bcbb71f776e960a71114b15cfdc315109de4c7c846a8ed5"
    );
}
