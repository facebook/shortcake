// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Serialization round-trip tests for X-Wing types.

#![cfg(feature = "xwing")]

use rand_core::UnwrapErr;
use shortcake::{Kem, XWingCiphertext, XWingDecapsulationKey, XWingEncapsulationKey, XWingKem};

fn test_rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

#[test]
fn test_encapsulation_key_roundtrip() {
    let mut rng = test_rng();
    let (_dk, ek) = XWingKem::generate(&mut rng);

    let bytes = ek.as_bytes();
    let ek2 = XWingEncapsulationKey::from_bytes(bytes).unwrap();

    assert_eq!(ek.as_ref(), ek2.as_ref());
}

#[test]
fn test_decapsulation_key_deterministic_from_seed() {
    let seed = [42u8; 32];
    let dk1 = XWingDecapsulationKey::from_seed(seed);
    let dk2 = XWingDecapsulationKey::from_seed(seed);
    assert_eq!(
        dk1.encapsulation_key().as_ref(),
        dk2.encapsulation_key().as_ref()
    );
}

#[test]
fn test_ciphertext_roundtrip() {
    let mut rng = test_rng();
    let (dk, ek) = XWingKem::generate(&mut rng);

    let (ct, ss1) = XWingKem::encaps(&ek, &mut rng).unwrap();

    let ct_bytes = ct.as_bytes();
    let ct2 = XWingCiphertext::from_bytes(ct_bytes).unwrap();

    let ss2 = XWingKem::decaps(&dk, &ct2).unwrap();
    assert_eq!(ss1.as_ref(), ss2.as_ref());
}

#[test]
fn test_encapsulation_key_as_ref() {
    let mut rng = test_rng();
    let (_dk, ek) = XWingKem::generate(&mut rng);

    let as_ref_bytes: &[u8] = ek.as_ref();
    assert_eq!(as_ref_bytes.len(), 1216);
}

#[test]
fn test_ciphertext_as_ref() {
    let mut rng = test_rng();
    let (_dk, ek) = XWingKem::generate(&mut rng);

    let (ct, _ss) = XWingKem::encaps(&ek, &mut rng).unwrap();
    let as_ref_bytes: &[u8] = ct.as_ref();
    assert_eq!(as_ref_bytes.len(), 1120);
}

#[test]
fn test_wrong_length_rejected() {
    assert!(XWingEncapsulationKey::from_bytes(&[0u8; 32]).is_none());
    assert!(XWingCiphertext::from_bytes(&[0u8; 32]).is_none());
}

#[test]
fn test_shared_secret_as_ref() {
    let mut rng = test_rng();
    let (_dk, ek) = XWingKem::generate(&mut rng);

    let (_ct, ss) = XWingKem::encaps(&ek, &mut rng).unwrap();

    let ss_bytes = ss.as_ref();
    assert_eq!(ss_bytes.len(), 32, "shared secret should be 32 bytes");
    assert!(
        ss_bytes.iter().any(|&b| b != 0),
        "shared secret should be non-zero"
    );
}

#[test]
fn test_kem_encaps_decaps_serialization_roundtrip() {
    let mut rng = test_rng();

    // Generate keypair
    let (dk, ek) = XWingKem::generate(&mut rng);

    // Serialize and deserialize the public key before encapsulating
    let ek_bytes = ek.as_bytes();
    let ek_restored = XWingEncapsulationKey::from_bytes(ek_bytes).unwrap();

    // Encapsulate with the restored key
    let (ct, ss1) = XWingKem::encaps(&ek_restored, &mut rng).unwrap();

    // Serialize and deserialize the ciphertext before decapsulating
    let ct_bytes = ct.as_bytes();
    let ct_restored = XWingCiphertext::from_bytes(ct_bytes).unwrap();

    // Decapsulate with the restored ciphertext
    let ss2 = XWingKem::decaps(&dk, &ct_restored).unwrap();

    assert_eq!(ss1.as_ref(), ss2.as_ref());
}
