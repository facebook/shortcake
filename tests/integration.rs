// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Integration tests for the full protocol flow.

#![cfg(feature = "x25519-sha256")]

use shortcake::{
    Companion, Error, Primary, X25519Ciphertext, X25519DecapsulationKey, X25519Sha256,
};

/// Full round-trip test: Companion <-> Primary exchange.
#[test]
fn test_full_protocol_roundtrip() {
    let mut rng = rand::thread_rng();

    // === Companion: Generate KEM keypair ===
    let companion_dk = X25519DecapsulationKey::generate(&mut rng);
    let companion_ek = companion_dk.encapsulation_key();

    // === Companion: Start protocol (Move 1) ===
    let (companion_state1, msg1) =
        Companion::<X25519Sha256>::start(&mut rng, companion_ek, companion_dk);

    // === Primary: Receive Move 1, send Move 2 ===
    let (primary_state1, msg2) =
        Primary::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();

    // === Companion: Receive Move 2, send Move 3 ===
    let (companion_state2, msg3) = companion_state1
        .handle_primary_response(msg2.ct, msg2.primary_nonce)
        .unwrap();

    // === Primary: Receive Move 3, verify commitment ===
    let primary_state2 = primary_state1
        .handle_companion_nonce(msg3.companion_nonce)
        .unwrap();

    // === Both sides: SAS must match ===
    assert_eq!(
        companion_state2.sas().as_bytes(),
        primary_state2.sas().as_bytes(),
        "SAS mismatch between Companion and Primary"
    );

    // === Both sides: Derive keys, must match ===
    let salt = b"test salt";
    let info = b"test info";

    let mut companion_key = [0u8; 32];
    let mut primary_key = [0u8; 32];

    companion_state2
        .finalize(salt, info, &mut companion_key)
        .unwrap();
    primary_state2
        .finalize(salt, info, &mut primary_key)
        .unwrap();

    assert_eq!(
        companion_key, primary_key,
        "Derived keys must match between Companion and Primary"
    );
}

/// Test that reflection attack is detected.
#[test]
fn test_reflection_attack_detected() {
    let mut rng = rand::thread_rng();

    // Generate keypair
    let companion_dk = X25519DecapsulationKey::generate(&mut rng);
    let companion_ek = companion_dk.encapsulation_key();

    // Start protocol
    let (companion_state1, _msg1) =
        Companion::<X25519Sha256>::start(&mut rng, companion_ek.clone(), companion_dk);

    // Simulate attacker reflecting the ek back as ciphertext
    // Create a ciphertext with the same bytes as ek
    let reflected_ct = X25519Ciphertext::from_bytes(companion_ek.to_bytes());
    let fake_nonce = [0u8; 32];

    let result = companion_state1.handle_primary_response(reflected_ct, fake_nonce);

    match result {
        Err(Error::ReflectionDetected) => {} // Expected
        Err(e) => panic!("Expected ReflectionDetected, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// Test that wrong nonce fails commitment verification.
#[test]
fn test_wrong_nonce_fails_commitment() {
    let mut rng = rand::thread_rng();

    // Companion generates keypair and starts
    let companion_dk = X25519DecapsulationKey::generate(&mut rng);
    let companion_ek = companion_dk.encapsulation_key();
    let (_companion_state1, msg1) =
        Companion::<X25519Sha256>::start(&mut rng, companion_ek, companion_dk);

    // Primary receives and responds
    let (primary_state1, _msg2) =
        Primary::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();

    // Attacker sends wrong nonce
    let wrong_nonce = [0xffu8; 32];
    let result = primary_state1.handle_companion_nonce(wrong_nonce);

    match result {
        Err(Error::CommitmentMismatch) => {} // Expected
        Err(e) => panic!("Expected CommitmentMismatch, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// Test that different salt/info produces different keys.
#[test]
fn test_different_kdf_params_different_keys() {
    let mut rng = rand::thread_rng();

    // Run full protocol twice with same keys but different KDF params
    let companion_dk = X25519DecapsulationKey::generate(&mut rng);
    let companion_ek = companion_dk.encapsulation_key();

    let (companion_state1, msg1) =
        Companion::<X25519Sha256>::start(&mut rng, companion_ek, companion_dk);
    let (primary_state1, msg2) =
        Primary::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
    let (companion_state2, msg3) = companion_state1
        .handle_primary_response(msg2.ct, msg2.primary_nonce)
        .unwrap();
    let primary_state2 = primary_state1
        .handle_companion_nonce(msg3.companion_nonce)
        .unwrap();

    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];

    companion_state2
        .finalize(b"salt1", b"info", &mut key1)
        .unwrap();
    primary_state2
        .finalize(b"salt2", b"info", &mut key2)
        .unwrap();

    assert_ne!(key1, key2, "Different salt should produce different keys");
}
