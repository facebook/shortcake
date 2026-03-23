// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Full 3-move SAS protocol demo using the X-Wing + SHA3-256 ciphersuite.
//!
//! Run with:
//! ```sh
//! cargo run --example protocol --features xwing
//! ```

use rand_core::UnwrapErr;
use shortcake::{Initiator, Responder, XWingSha3};

fn main() {
    let mut rng = UnwrapErr(getrandom::SysRng);

    // Move 1: Initiator starts
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);

    // Move 2: Responder processes msg1
    let (responder, msg2) =
        Responder::<XWingSha3>::start(&mut rng, msg1).expect("Responder failed to start");

    // Move 3: Initiator processes msg2
    let (i_code, msg3) = initiator.finish(msg2).expect("Initiator failed to finish");

    // Responder processes msg3
    let r_code = responder.finish(msg3).expect("Responder failed to finish");

    // Both parties display their codes for out-of-band comparison
    let r_code_bytes = r_code.as_bytes().to_vec();
    let i_code_bytes = i_code.as_bytes().to_vec();

    println!("Initiator code: {:02x?}", i_code_bytes);
    println!("Responder code: {:02x?}", r_code_bytes);
    assert_eq!(i_code_bytes, r_code_bytes, "Verification codes must match");

    // After human confirms codes match, verify programmatically
    let i_secret = i_code
        .verify(&r_code_bytes)
        .expect("Verification failed on initiator side");
    let r_secret = r_code
        .verify(&i_code_bytes)
        .expect("Verification failed on responder side");
    assert_eq!(
        i_secret.as_ref(),
        r_secret.as_ref(),
        "Shared secrets must match"
    );

    println!("Protocol complete!");
}
