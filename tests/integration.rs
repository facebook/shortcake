// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Integration tests for the full protocol flow.

#![cfg(feature = "x25519-sha256")]

use shortcake::{Error, Initiator, Responder, X25519Sha256};

/// Full round-trip test: Initiator <-> Responder exchange.
#[test]
fn test_full_protocol_roundtrip() {
    let mut rng = rand::thread_rng();

    // Move 1: Initiator starts
    let (initiator, msg1) = Initiator::<X25519Sha256>::start(&mut rng);

    // Move 2: Responder processes msg1
    let (responder, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1).unwrap();

    // Move 3: Initiator processes msg2
    let (i_code, msg3) = initiator.finish(msg2).unwrap();

    // Responder processes msg3
    let r_code = responder.finish(msg3).unwrap();

    // Verification codes must match
    assert_eq!(
        i_code.as_bytes(),
        r_code.as_bytes(),
        "Verification codes must match between Initiator and Responder"
    );

    // Verify and obtain shared secrets
    let r_code_bytes = r_code.as_bytes().to_vec();
    let i_code_bytes = i_code.as_bytes().to_vec();

    let i_secret = i_code.verify(&r_code_bytes).unwrap();
    let r_secret = r_code.verify(&i_code_bytes).unwrap();

    assert_eq!(
        i_secret.as_ref(),
        r_secret.as_ref(),
        "Shared secrets must match between Initiator and Responder"
    );
}

/// Test that verification with wrong code fails.
#[test]
fn test_verification_code_mismatch() {
    let mut rng = rand::thread_rng();

    let (initiator, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
    let (responder, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1).unwrap();
    let (i_code, msg3) = initiator.finish(msg2).unwrap();
    let _r_code = responder.finish(msg3).unwrap();

    // Try verifying with wrong bytes
    let wrong_bytes = [0xffu8; 5];
    let result = i_code.verify(&wrong_bytes);

    match result {
        Err(Error::VerificationFailed) => {} // Expected
        Err(e) => panic!("Expected VerificationFailed, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// Test that verification with wrong length fails.
#[test]
fn test_verification_wrong_length() {
    let mut rng = rand::thread_rng();

    let (initiator, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
    let (responder, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1).unwrap();
    let (i_code, msg3) = initiator.finish(msg2).unwrap();
    let _r_code = responder.finish(msg3).unwrap();

    // Try verifying with wrong length
    let wrong_length = [0u8; 3];
    let result = i_code.verify(&wrong_length);

    match result {
        Err(Error::VerificationFailed) => {} // Expected
        Err(e) => panic!("Expected VerificationFailed, got {:?}", e),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}
