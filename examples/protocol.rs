// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Full 3-move SAS protocol demo using the X-Wing + SHA3-256 ciphersuite,
//! with serialization/deserialization of all protocol states and messages.
//!
//! Run with:
//! ```sh
//! cargo run --example protocol --features "xwing serde"
//! ```

use rand_core::UnwrapErr;
use shortcake::{Initiator, Responder, XWingSha3};

fn main() {
    let mut initiator_rng = UnwrapErr(getrandom::SysRng);
    let mut responder_rng = UnwrapErr(getrandom::SysRng);

    // Move 1: Initiator starts
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut initiator_rng);

    // Serialize initiator state (to be restored later for Move 3)
    let initiator_bytes = postcard::to_allocvec(&initiator).expect("Failed to serialize Initiator");
    println!(
        "initiator bytes ({} bytes): {:?}",
        initiator_bytes.len(),
        hex::encode(&initiator_bytes)
    );
    drop(initiator);

    // Serialize msg1 for transmission
    let msg1_bytes = postcard::to_allocvec(&msg1).expect("Failed to serialize MessageOne");
    println!(
        "msg1 bytes ({} bytes): {:?}",
        msg1_bytes.len(),
        hex::encode(&msg1_bytes)
    );

    // Move 2: Responder deserializes msg1 and processes it
    let msg1_deserialized =
        postcard::from_bytes(&msg1_bytes).expect("Failed to deserialize MessageOne");
    let (responder, msg2) = Responder::<XWingSha3>::start(&mut responder_rng, msg1_deserialized)
        .expect("Responder failed to start");

    // Serialize responder state (to be restored later)
    let responder_bytes = postcard::to_allocvec(&responder).expect("Failed to serialize Responder");
    println!(
        "responder bytes ({} bytes): {:?}",
        responder_bytes.len(),
        hex::encode(&responder_bytes)
    );
    drop(responder);

    // Serialize msg2 for transmission
    let msg2_bytes = postcard::to_allocvec(&msg2).expect("Failed to serialize MessageTwo");
    println!(
        "msg2 bytes ({} bytes): {:?}",
        msg2_bytes.len(),
        hex::encode(&msg2_bytes)
    );

    // Move 3: Initiator deserializes its state and msg2, then finishes
    let initiator_deserialized: Initiator<XWingSha3> =
        postcard::from_bytes(&initiator_bytes).expect("Failed to deserialize Initiator");
    let msg2_deserialized =
        postcard::from_bytes(&msg2_bytes).expect("Failed to deserialize MessageTwo");
    let (i_output, msg3) = initiator_deserialized
        .finish(msg2_deserialized)
        .expect("Initiator failed to finish");

    // Serialize msg3 for transmission
    let msg3_bytes = postcard::to_allocvec(&msg3).expect("Failed to serialize MessageThree");
    println!(
        "msg3 bytes ({} bytes): {:?}",
        msg3_bytes.len(),
        hex::encode(&msg3_bytes)
    );

    // Responder deserializes its state and msg3, then finishes
    let responder_deserialized: Responder<XWingSha3> =
        postcard::from_bytes(&responder_bytes).expect("Failed to deserialize Responder");
    let msg3_deserialized =
        postcard::from_bytes(&msg3_bytes).expect("Failed to deserialize MessageThree");
    let r_output = responder_deserialized
        .finish(msg3_deserialized)
        .expect("Responder failed to finish");

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

    println!(
        "shared secret ({} bytes): {:?}",
        i_secret.as_ref().len(),
        hex::encode(i_secret.as_ref())
    );
    println!("Protocol complete!");
}
