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
use shortcake::{Error, Initiator, Responder, XWingSha3};

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
    let i_secret = i_output.into_shared_secret();
    let r_secret = r_output.into_shared_secret();

    assert_eq!(
        i_secret.as_ref(),
        r_secret.as_ref(),
        "Shared secrets must match between Initiator and Responder"
    );
}

#[test]
fn test_commitment_mismatch_wrong_msg3() {
    let mut rng = test_rng();

    // Session A
    let (init_a, msg1_a) = Initiator::<XWingSha3>::start(&mut rng);
    let (resp_a, msg2_a) = Responder::<XWingSha3>::start(&mut rng, msg1_a).unwrap();
    let (_out_a, msg3_a) = init_a.finish(msg2_a).unwrap();

    // Session B
    let (init_b, msg1_b) = Initiator::<XWingSha3>::start(&mut rng);
    let (_resp_b, msg2_b) = Responder::<XWingSha3>::start(&mut rng, msg1_b).unwrap();
    let (_out_b, msg3_b) = init_b.finish(msg2_b).unwrap();

    // Feed session B's msg3 to session A's responder — nonce won't match commitment
    match resp_a.finish(msg3_b) {
        Err(Error::CommitmentMismatch) => {}
        Err(e) => panic!("expected CommitmentMismatch, got {e:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }

    // Correct msg3 would have worked (consumed above, so just verify the error path)
    let _ = msg3_a;
}

#[test]
fn test_cross_session_sas_differs() {
    let mut rng = test_rng();

    // Run two independent sessions
    let (init1, msg1a) = Initiator::<XWingSha3>::start(&mut rng);
    let (resp1, msg2a) = Responder::<XWingSha3>::start(&mut rng, msg1a).unwrap();
    let (out1_i, msg3a) = init1.finish(msg2a).unwrap();
    let out1_r = resp1.finish(msg3a).unwrap();

    let (init2, msg1b) = Initiator::<XWingSha3>::start(&mut rng);
    let (resp2, msg2b) = Responder::<XWingSha3>::start(&mut rng, msg1b).unwrap();
    let (out2_i, msg3b) = init2.finish(msg2b).unwrap();
    let out2_r = resp2.finish(msg3b).unwrap();

    // SAS codes within each session match
    assert_eq!(out1_i.sas_code(), out1_r.sas_code());
    assert_eq!(out2_i.sas_code(), out2_r.sas_code());

    // SAS codes across sessions differ (with overwhelming probability)
    assert_ne!(out1_i.sas_code(), out2_i.sas_code());
}
