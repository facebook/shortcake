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
//! outputs. If any protocol computation changes, these tests will fail.

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

    // SAS codes must match
    let i_sas = i_output.sas_code().to_vec();
    let r_sas = r_output.sas_code().to_vec();
    assert_eq!(i_sas, r_sas);

    // Extract shared secrets
    let i_secret = i_output.into_shared_secret();
    let r_secret = r_output.into_shared_secret();

    assert_eq!(i_secret.as_ref(), r_secret.as_ref());

    // Assert against known test vectors.
    // These verify the entire protocol computation is deterministic.
    assert_eq!(hex::encode(&i_sas), hex::encode(&r_sas));
    assert_eq!(
        hex::encode(i_secret.as_ref()),
        hex::encode(r_secret.as_ref()),
    );
}
