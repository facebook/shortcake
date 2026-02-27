// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Integration tests for the full protocol flow with ML-KEM-768.

#![cfg(feature = "mlkem768-sha256")]

use shortcake::{Error, Initiator, MlKem768DecapsulationKey, MlKem768Sha256, Responder};

/// Full round-trip test: Initiator <-> Responder exchange.
#[test]
fn test_full_protocol_roundtrip_mlkem() {
    let mut rng = rand::thread_rng();

    // === Initiator: Generate KEM keypair ===
    let initiator_dk = MlKem768DecapsulationKey::generate(&mut rng);
    let initiator_ek = initiator_dk.encapsulation_key();

    // === Initiator: Start protocol (Move 1) ===
    let (initiator_state1, msg1) =
        Initiator::<MlKem768Sha256>::start(&mut rng, initiator_ek, initiator_dk);

    // === Responder: Receive Move 1, send Move 2 ===
    let (responder_state1, msg2) =
        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();

    // === Initiator: Receive Move 2, send Move 3 ===
    let (initiator_state2, msg3) = initiator_state1
        .handle_responder_response(msg2.ct, msg2.responder_nonce)
        .unwrap();

    // === Responder: Receive Move 3, verify commitment ===
    let responder_state2 = responder_state1
        .handle_initiator_nonce(msg3.initiator_nonce)
        .unwrap();

    // === Both sides: SAS must match ===
    assert_eq!(
        initiator_state2.sas().as_bytes(),
        responder_state2.sas().as_bytes(),
        "SAS mismatch between Initiator and Responder"
    );

    // === Both sides: Derive keys, must match ===
    let salt = b"test salt";
    let info = b"test info";

    let mut initiator_key = [0u8; 32];
    let mut responder_key = [0u8; 32];

    initiator_state2
        .finalize(salt, info, &mut initiator_key)
        .unwrap();
    responder_state2
        .finalize(salt, info, &mut responder_key)
        .unwrap();

    assert_eq!(
        initiator_key, responder_key,
        "Derived keys must match between Initiator and Responder"
    );
}

/// Test that wrong nonce fails commitment verification.
#[test]
fn test_wrong_nonce_fails_commitment_mlkem() {
    let mut rng = rand::thread_rng();

    // Initiator generates keypair and starts
    let initiator_dk = MlKem768DecapsulationKey::generate(&mut rng);
    let initiator_ek = initiator_dk.encapsulation_key();
    let (_initiator_state1, msg1) =
        Initiator::<MlKem768Sha256>::start(&mut rng, initiator_ek, initiator_dk);

    // Responder receives and responds
    let (responder_state1, _msg2) =
        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();

    // Attacker sends wrong nonce
    let wrong_nonce = [0xffu8; 32];
    let result = responder_state1.handle_initiator_nonce(wrong_nonce);

    match result {
        Err(Error::CommitmentMismatch) => {} // Expected
        Err(e) => panic!("Expected CommitmentMismatch, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// Test that different salt/info produces different keys.
#[test]
fn test_different_kdf_params_different_keys_mlkem() {
    let mut rng = rand::thread_rng();

    let initiator_dk = MlKem768DecapsulationKey::generate(&mut rng);
    let initiator_ek = initiator_dk.encapsulation_key();

    let (initiator_state1, msg1) =
        Initiator::<MlKem768Sha256>::start(&mut rng, initiator_ek, initiator_dk);
    let (responder_state1, msg2) =
        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
    let (initiator_state2, msg3) = initiator_state1
        .handle_responder_response(msg2.ct, msg2.responder_nonce)
        .unwrap();
    let responder_state2 = responder_state1
        .handle_initiator_nonce(msg3.initiator_nonce)
        .unwrap();

    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];

    initiator_state2
        .finalize(b"salt1", b"info", &mut key1)
        .unwrap();
    responder_state2
        .finalize(b"salt2", b"info", &mut key2)
        .unwrap();

    assert_ne!(key1, key2, "Different salt should produce different keys");
}
