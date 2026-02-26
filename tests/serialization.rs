// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Serialization round-trip tests for X25519 types.

#![cfg(feature = "x25519-sha256")]

use shortcake::{
    Kem, X25519Ciphertext, X25519DecapsulationKey, X25519EncapsulationKey, X25519Kem,
};

#[test]
fn test_encapsulation_key_roundtrip() {
    let mut rng = rand::thread_rng();
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();

    let bytes = ek.to_bytes();
    let ek2 = X25519EncapsulationKey::from_bytes(bytes);

    assert_eq!(ek.to_bytes(), ek2.to_bytes());
}

#[test]
fn test_decapsulation_key_deterministic_from_bytes() {
    // Verify that constructing a decapsulation key from the same bytes
    // deterministically produces the same encapsulation (public) key.
    let known_bytes = [42u8; 32];
    let dk1 = X25519DecapsulationKey::from_bytes(known_bytes);
    let dk2 = X25519DecapsulationKey::from_bytes(known_bytes);
    assert_eq!(dk1.encapsulation_key().to_bytes(), dk2.encapsulation_key().to_bytes());
}

#[test]
fn test_ciphertext_roundtrip() {
    let bytes = [7u8; 32];
    let ct = X25519Ciphertext::from_bytes(bytes);
    let ct_bytes = ct.to_bytes();
    assert_eq!(bytes, ct_bytes);

    let ct2 = X25519Ciphertext::from_bytes(ct_bytes);
    assert_eq!(ct.to_bytes(), ct2.to_bytes());
}

#[test]
fn test_encapsulation_key_as_ref() {
    let ek = X25519EncapsulationKey::from_bytes([5u8; 32]);
    let as_ref_bytes: &[u8] = ek.as_ref();
    assert_eq!(as_ref_bytes, &ek.to_bytes());
}

#[test]
fn test_ciphertext_as_ref() {
    let ct = X25519Ciphertext::from_bytes([9u8; 32]);
    let as_ref_bytes: &[u8] = ct.as_ref();
    assert_eq!(as_ref_bytes, &ct.to_bytes());
}

#[test]
fn test_encapsulation_key_zero_bytes_roundtrip() {
    let bytes = [0u8; 32];
    let ek = X25519EncapsulationKey::from_bytes(bytes);
    assert_eq!(ek.to_bytes(), bytes);

    let ek2 = X25519EncapsulationKey::from_bytes(ek.to_bytes());
    assert_eq!(ek.to_bytes(), ek2.to_bytes());
}

#[test]
fn test_encapsulation_key_all_ones_roundtrip() {
    let bytes = [0xFFu8; 32];
    let ek = X25519EncapsulationKey::from_bytes(bytes);
    let roundtripped = X25519EncapsulationKey::from_bytes(ek.to_bytes());
    assert_eq!(ek.to_bytes(), roundtripped.to_bytes());
}

#[test]
fn test_ciphertext_zero_bytes_roundtrip() {
    let bytes = [0u8; 32];
    let ct = X25519Ciphertext::from_bytes(bytes);
    assert_eq!(ct.to_bytes(), bytes);

    let ct2 = X25519Ciphertext::from_bytes(ct.to_bytes());
    assert_eq!(ct.to_bytes(), ct2.to_bytes());
}

#[test]
fn test_ciphertext_all_ones_roundtrip() {
    let bytes = [0xFFu8; 32];
    let ct = X25519Ciphertext::from_bytes(bytes);
    let roundtripped = X25519Ciphertext::from_bytes(ct.to_bytes());
    assert_eq!(ct.to_bytes(), roundtripped.to_bytes());
}

#[test]
fn test_shared_secret_as_ref() {
    let mut rng = rand::thread_rng();
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();

    let (_ct, ss) = X25519Kem::encaps(&ek, &mut rng).unwrap();

    let ss_bytes = ss.as_ref();
    assert_eq!(ss_bytes.len(), 32, "shared secret should be 32 bytes");
    assert!(
        ss_bytes.iter().any(|&b| b != 0),
        "shared secret should be non-zero"
    );
}

#[test]
fn test_kem_encaps_decaps_serialization_roundtrip() {
    let mut rng = rand::thread_rng();

    // Generate keypair
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();

    // Serialize and deserialize the public key before encapsulating
    let ek_bytes = ek.to_bytes();
    let ek_restored = X25519EncapsulationKey::from_bytes(ek_bytes);

    // Encapsulate with the restored key
    let (ct, ss1) = X25519Kem::encaps(&ek_restored, &mut rng).unwrap();

    // Serialize and deserialize the ciphertext before decapsulating
    let ct_bytes = ct.to_bytes();
    let ct_restored = X25519Ciphertext::from_bytes(ct_bytes);

    // Decapsulate with the restored ciphertext
    let ss2 = X25519Kem::decaps(&dk, &ct_restored).unwrap();

    assert_eq!(ss1.as_ref(), ss2.as_ref());
}
