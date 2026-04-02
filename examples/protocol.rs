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
    let (i_output, msg3) = initiator.finish(msg2).expect("Initiator failed to finish");

    // Responder processes msg3
    let r_output = responder.finish(msg3).expect("Responder failed to finish");

    // Both parties display their SAS codes for out-of-band comparison
    println!("Initiator SAS: {:02x?}", i_output.sas_code());
    println!("Responder SAS: {:02x?}", r_output.sas_code());
    assert_eq!(
        i_output.sas_code(),
        r_output.sas_code(),
        "SAS codes must match"
    );

    // After human confirms SAS codes match, extract shared secrets
    let i_secret = i_output.into_shared_secret();
    let r_secret = r_output.into_shared_secret();
    assert_eq!(
        i_secret.as_ref(),
        r_secret.as_ref(),
        "Shared secrets must match"
    );

    println!("Protocol complete!");
}
