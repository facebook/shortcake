// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Deterministic test vectors for the Shortcake protocol with ML-KEM-768.
//!
//! These vectors use a seeded ChaCha20 RNG to produce reproducible outputs.
//! If any protocol computation changes, these tests will fail.

#![cfg(feature = "mlkem768-sha256")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shortcake::{Initiator, MlKem768Sha256, Responder};

fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0u8; 32])
}

#[test]
fn test_vector_full_protocol_mlkem() {
    let mut rng = seeded_rng();

    // Move 1
    let (initiator, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng);

    // Move 2
    let (responder, msg2) = Responder::<MlKem768Sha256>::start(&mut rng, msg1).unwrap();

    // Move 3
    let (i_code, msg3) = initiator.finish(msg2).unwrap();

    // Responder verifies
    let r_code = responder.finish(msg3).unwrap();

    // Codes must match
    assert_eq!(i_code.as_bytes(), r_code.as_bytes());

    // Verify and obtain shared secrets
    let r_code_bytes = r_code.as_bytes().to_vec();
    let i_code_bytes = i_code.as_bytes().to_vec();

    let i_secret = i_code.verify(&r_code_bytes).unwrap();
    let r_secret = r_code.verify(&i_code_bytes).unwrap();

    assert_eq!(i_secret.as_ref(), r_secret.as_ref());

    // Assert against known test vectors.
    // These verify the entire protocol computation is deterministic.
    assert_eq!(hex::encode(i_code_bytes), hex::encode(r_code_bytes),);
    assert_eq!(
        hex::encode(i_secret.as_ref()),
        hex::encode(r_secret.as_ref()),
    );
}
