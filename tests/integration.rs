// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Integration tests for the full protocol flow.

#![cfg(feature = "xwing")]

use rand_core::UnwrapErr;
use shortcake::{Initiator, Responder, XWingSha3};

fn test_rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

/// Full round-trip test: Initiator <-> Responder exchange.
#[test]
fn test_full_protocol_roundtrip() {
    let mut rng = test_rng();

    // Move 1: Initiator starts
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);

    // Move 2: Responder processes msg1
    let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();

    // Move 3: Initiator processes msg2
    let (i_output, msg3) = initiator.finish(msg2).unwrap();

    // Responder processes msg3
    let r_output = responder.finish(msg3).unwrap();

    // SAS codes must match
    assert_eq!(
        i_output.sas_code(),
        r_output.sas_code(),
        "SAS codes must match between Initiator and Responder"
    );

    // Extract shared secrets
    let i_secret = i_output.into_session_key();
    let r_secret = r_output.into_session_key();

    assert_eq!(
        i_secret.as_slice(),
        r_secret.as_slice(),
        "Shared secrets must match between Initiator and Responder"
    );
}
