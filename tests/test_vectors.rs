// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Deterministic test vectors for the Shortcake protocol.
//!
//! These vectors use a simple counter-based seeded RNG to produce reproducible
//! outputs. If any protocol computation changes, these tests will fail,
//! making non-backwards-compatible changes immediately obvious.

#![cfg(feature = "xwing")]

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use shortcake::{Initiator, Responder, XWingSha3};

/// A simple deterministic RNG for test vectors.
struct SeededRng {
    counter: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { counter: seed }
    }
}

impl TryRng for SeededRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.counter.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for SeededRng {}

// Pinned test vectors. If these fail, the protocol output has changed
// in a non-backwards-compatible way. Update only after deliberate
// protocol changes.
const EXPECTED_SAS: &str = "067033da8c19def9414c436e5ebb852beafde90254db9c29db992875081429ca";
const EXPECTED_SESSION_KEY: &str =
    "16b56ef77ca1e16d12d05c45a2d47a308b7f16aa27ab00617d2fb78219f3627c";
#[test]
fn test_vector_full_protocol() {
    let mut rng = SeededRng::new(0);

    // Move 1
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);

    // Move 2
    let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();

    // Move 3
    let (i_output, msg3) = initiator.finish(msg2).unwrap();

    // Responder verifies
    let r_output = responder.finish(msg3).unwrap();

    // Both sides must produce identical SAS and session key
    let i_sas = i_output.sas_code().to_vec();
    let r_sas = r_output.sas_code().to_vec();
    assert_eq!(i_sas, r_sas, "SAS mismatch between Initiator and Responder");

    let i_key = i_output.into_session_key();
    let r_key = r_output.into_session_key();
    assert_eq!(
        i_key.as_slice(),
        r_key.as_slice(),
        "session key mismatch between Initiator and Responder"
    );

    // Check against pinned test vectors
    assert_eq!(hex::encode(&i_sas), EXPECTED_SAS, "SAS changed");
    assert_eq!(
        hex::encode(i_key.as_slice()),
        EXPECTED_SESSION_KEY,
        "session key changed"
    );
}
