// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Deterministic test vectors for the Shortcake protocol.
//!
//! These vectors use ChaCha20Rng (seeded with zeros) to produce reproducible
//! outputs. If any protocol computation changes, these tests will fail,
//! making non-backwards-compatible changes immediately obvious.
//!
//! To regenerate the test vectors file after a deliberate protocol change:
//! ```sh
//! SHORTCAKE_GENERATE_TEST_VECTORS=tests/full_test_vectors.txt \
//!     cargo test --all-features -- generate_test_vectors
//! ```

#![cfg(feature = "xwing")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shortcake::{Initiator, Responder, XWingSha3};

fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0u8; 32])
}

fn parse_vectors(s: &str) -> Vec<(&str, &str)> {
    s.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once(": ").expect("expected 'key: value'");
            (k, v)
        })
        .collect()
}

fn expect_vector<'a>(vectors: &'a [(&str, &str)], key: &str) -> &'a str {
    vectors
        .iter()
        .find(|(k, _)| *k == key)
        .unwrap_or_else(|| panic!("missing key '{key}' in test vectors file"))
        .1
}

fn assert_pinned(key: &str, actual: &str, vectors: &[(&str, &str)]) {
    assert_eq!(
        actual,
        expect_vector(vectors, key),
        "{key} does not match pinned test vector — protocol output has changed"
    );
}

// === Tests without serde (run with just --features xwing) ===

/// Checks SAS against pinned value.
#[test]
fn test_pinned_sas() {
    let mut rng = test_rng();
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let (i_output, msg3) = initiator.finish(msg2).unwrap();
    let r_output = responder.finish(msg3).unwrap();

    let i_sas = hex::encode(i_output.sas_code());
    let r_sas = hex::encode(r_output.sas_code());
    assert_eq!(i_sas, r_sas, "SAS mismatch between Initiator and Responder");

    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned("sas", &i_sas, &vectors);
}

/// Checks session key against pinned value.
#[test]
fn test_pinned_session_key() {
    let mut rng = test_rng();
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let (i_output, msg3) = initiator.finish(msg2).unwrap();
    let r_output = responder.finish(msg3).unwrap();

    let i_key = i_output.into_session_key();
    let r_key = r_output.into_session_key();
    assert_eq!(
        i_key.as_slice(),
        r_key.as_slice(),
        "session key mismatch between Initiator and Responder"
    );

    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned("session_key", &hex::encode(i_key.as_slice()), &vectors);
}

// === Tests with serde (run with --all-features) ===

/// Checks serialized MessageOne (ek + commitment) against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_msg1() {
    let mut rng = test_rng();
    let (_initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "msg1",
        &hex::encode(postcard::to_allocvec(&msg1).unwrap()),
        &vectors,
    );
}

/// Checks serialized MessageTwo (ct + responder_nonce) against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_msg2() {
    let mut rng = test_rng();
    let (_initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (_responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "msg2",
        &hex::encode(postcard::to_allocvec(&msg2).unwrap()),
        &vectors,
    );
}

/// Checks serialized MessageThree (initiator_nonce) against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_msg3() {
    let mut rng = test_rng();
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (_responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let (_i_output, msg3) = initiator.finish(msg2).unwrap();
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "msg3",
        &hex::encode(postcard::to_allocvec(&msg3).unwrap()),
        &vectors,
    );
}

/// Checks serialized Initiator state against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_initiator_state() {
    let mut rng = test_rng();
    let (initiator, _msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "initiator_state",
        &hex::encode(postcard::to_allocvec(&initiator).unwrap()),
        &vectors,
    );
}

/// Checks serialized Responder state against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_responder_state() {
    let mut rng = test_rng();
    let (_initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (responder, _msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "responder_state",
        &hex::encode(postcard::to_allocvec(&responder).unwrap()),
        &vectors,
    );
}

/// Checks serialized initiator ProtocolOutput against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_initiator_output() {
    let mut rng = test_rng();
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (_responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let (i_output, _msg3) = initiator.finish(msg2).unwrap();
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "initiator_output",
        &hex::encode(postcard::to_allocvec(&i_output).unwrap()),
        &vectors,
    );
}

/// Checks serialized responder ProtocolOutput against pinned value.
#[cfg(feature = "serde")]
#[test]
fn test_pinned_responder_output() {
    let mut rng = test_rng();
    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let (_i_output, msg3) = initiator.finish(msg2).unwrap();
    let r_output = responder.finish(msg3).unwrap();
    let vectors = parse_vectors(include_str!("full_test_vectors.txt"));
    assert_pinned(
        "responder_output",
        &hex::encode(postcard::to_allocvec(&r_output).unwrap()),
        &vectors,
    );
}

// === Generator ===

#[cfg(feature = "serde")]
#[test]
fn generate_test_vectors() {
    let mut rng = test_rng();

    let (initiator, msg1) = Initiator::<XWingSha3>::start(&mut rng);
    let initiator_bytes = postcard::to_allocvec(&initiator).unwrap();
    let msg1_bytes = postcard::to_allocvec(&msg1).unwrap();

    let (responder, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
    let responder_bytes = postcard::to_allocvec(&responder).unwrap();
    let msg2_bytes = postcard::to_allocvec(&msg2).unwrap();

    let (i_output, msg3) = initiator.finish(msg2).unwrap();
    let msg3_bytes = postcard::to_allocvec(&msg3).unwrap();
    let i_output_bytes = postcard::to_allocvec(&i_output).unwrap();

    let r_output = responder.finish(msg3).unwrap();
    let r_output_bytes = postcard::to_allocvec(&r_output).unwrap();

    let sas = hex::encode(i_output.sas_code());
    let session_key = hex::encode(i_output.into_session_key().as_slice());

    let vectors = [
        ("initiator_state", hex::encode(&initiator_bytes)),
        ("msg1", hex::encode(&msg1_bytes)),
        ("responder_state", hex::encode(&responder_bytes)),
        ("msg2", hex::encode(&msg2_bytes)),
        ("msg3", hex::encode(&msg3_bytes)),
        ("initiator_output", hex::encode(&i_output_bytes)),
        ("responder_output", hex::encode(&r_output_bytes)),
        ("sas", sas),
        ("session_key", session_key),
    ];

    let mut output = String::new();
    output.push_str("# Shortcake XWingSha3 test vectors (auto-generated)\n");
    output.push_str("# To regenerate:\n");
    output.push_str("#   SHORTCAKE_GENERATE_TEST_VECTORS=tests/full_test_vectors.txt \\\n");
    output.push_str("#       cargo test --all-features -- generate_test_vectors\n\n");
    for (k, v) in &vectors {
        output.push_str(&format!("{k}: {v}\n"));
    }

    if let Ok(path) = std::env::var("SHORTCAKE_GENERATE_TEST_VECTORS") {
        std::fs::write(&path, &output).unwrap();
        eprintln!("Wrote test vectors to {path}");
    } else {
        eprintln!("{output}");
    }
}
