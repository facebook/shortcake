// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Tests that secret types are properly zeroed on drop.

#![cfg(feature = "x25519-sha256")]

use core::mem::ManuallyDrop;
use core::ptr;

use shortcake::{
    Initiator, InitiatorAwaitingResponse, Kem, Responder, ResponderAwaitingNonce,
    X25519DecapsulationKey, X25519Kem, X25519Sha256,
};

#[test]
fn test_decapsulation_key_zeroize_on_drop() {
    let mut rng = rand::thread_rng();

    let mut dk = ManuallyDrop::new(X25519DecapsulationKey::generate(&mut rng));

    // Verify the key is non-zero before drop
    let ek_before = dk.encapsulation_key();
    let ek_bytes = ek_before.to_bytes();
    assert_ne!(ek_bytes, [0u8; 32], "key should be non-zero before drop");

    // Capture a raw pointer to the 32-byte `bytes` field (first field of the struct)
    let raw_ptr = &*dk as *const X25519DecapsulationKey as *const [u8; 32];

    // Trigger ZeroizeOnDrop (ManuallyDrop prevents double-drop at scope exit)
    unsafe { ptr::drop_in_place(&mut *dk) };

    // Read the raw bytes via read_volatile to prevent the compiler from
    // optimizing away the read of the dropped value.
    let raw_bytes = unsafe { ptr::read_volatile(raw_ptr) };
    assert_eq!(
        raw_bytes, [0u8; 32],
        "decapsulation key bytes should be zeroed after drop"
    );
}

#[test]
fn test_shared_secret_zeroize_on_drop() {
    let mut rng = rand::thread_rng();

    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();

    let (_ct, ss) = X25519Kem::encaps(&ek, &mut rng).unwrap();
    let mut ss = ManuallyDrop::new(ss);

    // Verify shared secret is non-zero
    assert!(
        ss.as_ref().iter().any(|&b| b != 0),
        "shared secret should be non-zero before drop"
    );

    // Capture a raw pointer to the inner 32 bytes
    let raw_ptr = &*ss as *const _ as *const [u8; 32];

    // Trigger ZeroizeOnDrop (ManuallyDrop prevents double-drop at scope exit)
    unsafe { ptr::drop_in_place(&mut *ss) };

    // Read via read_volatile to prevent optimization
    let raw_bytes = unsafe { ptr::read_volatile(raw_ptr) };
    assert_eq!(
        raw_bytes, [0u8; 32],
        "shared secret should be zeroed after drop"
    );
}

#[test]
fn test_initiator_awaiting_response_zeroize_on_drop() {
    let mut rng = rand::thread_rng();

    // Run the protocol to create an InitiatorAwaitingResponse state
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();
    let (state, _msg) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
    let mut state = ManuallyDrop::new(state);

    let size = core::mem::size_of::<InitiatorAwaitingResponse<X25519Sha256>>();

    // Verify the struct memory is not all-zero before drop
    let raw_ptr = &*state as *const InitiatorAwaitingResponse<X25519Sha256> as *const u8;
    let bytes_before: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_before.iter().any(|&b| b != 0),
        "state should contain non-zero bytes before drop"
    );

    // Trigger drop (which zeros nonce, dk, and ek)
    // ManuallyDrop prevents double-drop at scope exit.
    unsafe { ptr::drop_in_place(&mut *state) };

    // Read the entire struct's memory after drop
    let bytes_after: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_after.iter().all(|&b| b == 0),
        "all bytes of InitiatorAwaitingResponse should be zeroed after drop"
    );
}

#[test]
fn test_responder_awaiting_nonce_zeroize_on_drop() {
    let mut rng = rand::thread_rng();

    // Run the protocol to create a ResponderAwaitingNonce state
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();
    let (_initiator_state, first_msg) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);

    let (state, _resp_msg) =
        Responder::<X25519Sha256>::start(&mut rng, first_msg.ek, first_msg.commitment).unwrap();
    let mut state = ManuallyDrop::new(state);

    let size = core::mem::size_of::<ResponderAwaitingNonce<X25519Sha256>>();

    // Verify the struct memory is not all-zero before drop
    let raw_ptr = &*state as *const ResponderAwaitingNonce<X25519Sha256> as *const u8;
    let bytes_before: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_before.iter().any(|&b| b != 0),
        "state should contain non-zero bytes before drop"
    );

    // Trigger drop (which zeros responder_nonce, shared_secret, ek, commitment, ct)
    // ManuallyDrop prevents double-drop at scope exit.
    unsafe { ptr::drop_in_place(&mut *state) };

    // Read the entire struct's memory after drop
    let bytes_after: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_after.iter().all(|&b| b == 0),
        "all bytes of ResponderAwaitingNonce should be zeroed after drop"
    );
}
