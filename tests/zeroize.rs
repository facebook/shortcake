// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Tests that secret types are properly zeroed on drop.

#![cfg(feature = "xwing")]

use core::mem::ManuallyDrop;
use core::ptr;

use rand_core::UnwrapErr;
use shortcake::{Initiator, Kem, Responder, XWingDecapsulationKey, XWingKem, XWingSha3};

fn test_rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

#[test]
fn test_decapsulation_key_zeroize_on_drop() {
    let mut rng = test_rng();
    let (dk, _ek) = XWingKem::generate(&mut rng);
    let mut dk = ManuallyDrop::new(dk);

    // Verify the key is non-zero before drop
    let ek_before = dk.encapsulation_key();
    assert!(
        ek_before.as_ref().iter().any(|&b| b != 0),
        "key should produce non-zero encapsulation key"
    );

    let size = core::mem::size_of::<XWingDecapsulationKey>();
    let raw_ptr = &*dk as *const XWingDecapsulationKey as *const u8;

    // Trigger Drop (which zeroizes the entire inner key)
    unsafe { ptr::drop_in_place(&mut *dk) };

    let bytes_after: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_after.iter().all(|&b| b == 0),
        "all bytes of decapsulation key should be zeroed after drop"
    );
}

#[test]
fn test_shared_secret_zeroize_on_drop() {
    let mut rng = test_rng();
    let (_dk, ek) = XWingKem::generate(&mut rng);

    let (_ct, ss) = XWingKem::encaps(&ek, &mut rng).unwrap();
    let mut ss = ManuallyDrop::new(ss);

    // Verify shared secret is non-zero
    assert!(
        ss.as_ref().iter().any(|&b| b != 0),
        "shared secret should be non-zero before drop"
    );

    // Capture a raw pointer to the inner 32 bytes
    let raw_ptr = &*ss as *const _ as *const [u8; 32];

    // Trigger ZeroizeOnDrop
    unsafe { ptr::drop_in_place(&mut *ss) };

    let raw_bytes = unsafe { ptr::read_volatile(raw_ptr) };
    assert_eq!(
        raw_bytes, [0u8; 32],
        "shared secret should be zeroed after drop"
    );
}

#[test]
fn test_initiator_zeroize_on_drop() {
    let mut rng = test_rng();

    let (state, _msg) = Initiator::<XWingSha3>::start(&mut rng);
    let mut state = ManuallyDrop::new(state);

    let size = core::mem::size_of::<Initiator<XWingSha3>>();

    let raw_ptr = &*state as *const Initiator<XWingSha3> as *const u8;
    let bytes_before: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_before.iter().any(|&b| b != 0),
        "state should contain non-zero bytes before drop"
    );

    unsafe { ptr::drop_in_place(&mut *state) };

    let bytes_after: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_after.iter().all(|&b| b == 0),
        "all bytes of Initiator should be zeroed after drop"
    );
}

#[test]
fn test_responder_zeroize_on_drop() {
    let mut rng = test_rng();

    let (_initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);

    let (state, _msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let mut state = ManuallyDrop::new(state);

    let size = core::mem::size_of::<Responder<XWingSha3>>();

    let raw_ptr = &*state as *const Responder<XWingSha3> as *const u8;
    let bytes_before: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_before.iter().any(|&b| b != 0),
        "state should contain non-zero bytes before drop"
    );

    unsafe { ptr::drop_in_place(&mut *state) };

    let bytes_after: Vec<u8> = (0..size)
        .map(|i| unsafe { ptr::read_volatile(raw_ptr.add(i)) })
        .collect();
    assert!(
        bytes_after.iter().all(|&b| b == 0),
        "all bytes of Responder should be zeroed after drop"
    );
}
