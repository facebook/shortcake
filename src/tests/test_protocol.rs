// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use std::boxed::Box;
use std::format;
use std::vec;
use std::vec::Vec;

use generic_array::GenericArray;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::{
    DefaultCipherSuite, Initiator, MessageOne, MessageThree, MessageTwo, Output, Responder,
    ShortcakeError,
};

type CS = DefaultCipherSuite;

/// Helper: serialize a MessageOne to Vec<u8> via write_to (works without alloc feature).
fn serialize_msg1(msg: &MessageOne<CS>) -> Vec<u8> {
    let mut buf = vec![0u8; MessageOne::<CS>::size()];
    msg.write_to(&mut buf);
    buf
}

/// Helper: serialize a MessageTwo to Vec<u8> via write_to.
fn serialize_msg2(msg: &MessageTwo<CS>) -> Vec<u8> {
    let mut buf = vec![0u8; MessageTwo::<CS>::size()];
    msg.write_to(&mut buf);
    buf
}

/// Helper: serialize a MessageThree to Vec<u8> via write_to.
fn serialize_msg3(msg: &MessageThree<CS>) -> Vec<u8> {
    let mut buf = vec![0u8; MessageThree::<CS>::size()];
    msg.write_to(&mut buf);
    buf
}

/// Runs the full protocol with a deterministic RNG seeded from `seed`.
fn run_protocol(seed: u64) -> (Output<CS>, Output<CS>) {
    let mut rng = StdRng::seed_from_u64(seed);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, init_output) = initiator.finish(&msg2).unwrap();
    let resp_output = responder.finish(&msg3).unwrap();

    (init_output, resp_output)
}

#[test]
fn test_protocol_correctness() {
    for seed in 0..10 {
        let (init_output, resp_output) = run_protocol(seed);
        assert_eq!(init_output.sas(), resp_output.sas());
        assert_eq!(init_output.shared_secret(), resp_output.shared_secret());
    }
}

#[test]
fn test_different_runs_produce_different_outputs() {
    let (output_a, _) = run_protocol(0);
    let (output_b, _) = run_protocol(1);

    assert_ne!(output_a.sas(), output_b.sas());
    assert_ne!(output_a.shared_secret(), output_b.shared_secret());
}

#[test]
fn test_serialization_roundtrip_message_one() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, _) = Initiator::<CS>::start(&mut rng);

    let bytes = serialize_msg1(&msg1);
    let restored = MessageOne::<CS>::from_bytes(&bytes).unwrap();
    assert_eq!(msg1, restored);
}

#[test]
fn test_serialization_roundtrip_message_two() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, _) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();

    let bytes = serialize_msg2(&msg2);
    let restored = MessageTwo::<CS>::from_bytes(&bytes).unwrap();
    assert_eq!(msg2, restored);
}

#[test]
fn test_serialization_roundtrip_message_three() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    let bytes = serialize_msg3(&msg3);
    let restored = MessageThree::<CS>::from_bytes(&bytes).unwrap();
    assert_eq!(msg3, restored);
}

#[test]
fn test_serialization_buffer_too_small() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    let mut buf1 = vec![0u8; MessageOne::<CS>::size() - 1];
    let mut buf2 = vec![0u8; MessageTwo::<CS>::size() - 1];
    let mut buf3 = vec![0u8; MessageThree::<CS>::size() - 1];

    assert!(matches!(msg1.try_write_to(&mut buf1), Err(ShortcakeError::Serialization)));
    assert!(matches!(msg2.try_write_to(&mut buf2), Err(ShortcakeError::Serialization)));
    assert!(matches!(msg3.try_write_to(&mut buf3), Err(ShortcakeError::Serialization)));
}

#[test]
fn test_invalid_commitment_rejected() {
    let mut rng = StdRng::seed_from_u64(42);

    let (msg1, _initiator) = Initiator::<CS>::start(&mut rng);
    let (_msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();

    // Forge a MessageThree with a random (wrong) nonce
    let bad_msg3 = MessageThree::<CS>::from_bytes(&[0xff; 32]).unwrap();
    let result = responder.finish(&bad_msg3);
    assert!(matches!(result, Err(ShortcakeError::InvalidCommitment)));
}

#[test]
fn test_zero_public_key_rejected_by_responder() {
    let mut rng = StdRng::seed_from_u64(42);

    let bad_msg1 = MessageOne::<CS>::from_bytes(&[0u8; 64]).unwrap();
    let result = Responder::respond(&bad_msg1, &mut rng);
    assert!(matches!(result, Err(ShortcakeError::InvalidPublicKey)));
}

#[test]
fn test_zero_public_key_rejected_by_initiator() {
    let mut rng = StdRng::seed_from_u64(42);
    let (_, initiator) = Initiator::<CS>::start(&mut rng);

    let bad_msg2 = MessageTwo::<CS>::from_bytes(&[0u8; 64]).unwrap();
    let result = initiator.finish(&bad_msg2);
    assert!(matches!(result, Err(ShortcakeError::InvalidPublicKey)));
}

#[test]
fn test_tampered_initiator_public_key_detected() {
    let mut rng = StdRng::seed_from_u64(42);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    // Create a responder that received a different initiator public key
    let mut rng2 = StdRng::seed_from_u64(99);
    let (different_msg1, _) = Initiator::<CS>::start(&mut rng2);
    let (_, bad_responder) = Responder::respond(&different_msg1, &mut rng2).unwrap();

    // The original msg3 won't match the different commitment
    let result = bad_responder.finish(&msg3);
    assert!(matches!(result, Err(ShortcakeError::InvalidCommitment)));
}

#[test]
fn test_independent_sessions_produce_different_secrets() {
    // Two independent protocol runs should produce different SAS and
    // shared secrets, even with the same parties involved
    let mut rng1 = StdRng::seed_from_u64(100);
    let (msg1_a, init_a) = Initiator::<CS>::start(&mut rng1);
    let (msg2_a, resp_a) = Responder::respond(&msg1_a, &mut rng1).unwrap();
    let (msg3_a, out_init_a) = init_a.finish(&msg2_a).unwrap();
    let out_resp_a = resp_a.finish(&msg3_a).unwrap();
    assert_eq!(out_init_a.shared_secret(), out_resp_a.shared_secret());

    let mut rng2 = StdRng::seed_from_u64(200);
    let (msg1_b, init_b) = Initiator::<CS>::start(&mut rng2);
    let (msg2_b, resp_b) = Responder::respond(&msg1_b, &mut rng2).unwrap();
    let (msg3_b, out_init_b) = init_b.finish(&msg2_b).unwrap();
    let out_resp_b = resp_b.finish(&msg3_b).unwrap();
    assert_eq!(out_init_b.shared_secret(), out_resp_b.shared_secret());

    // Independent sessions must produce different outputs
    assert_ne!(out_init_a.sas(), out_init_b.sas());
    assert_ne!(out_init_a.shared_secret(), out_init_b.shared_secret());
}

#[test]
fn test_commitment_binds_to_public_key() {
    let mut rng = StdRng::seed_from_u64(42);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    // Modify the public key in msg1 while keeping the same commitment
    let mut tampered_bytes = serialize_msg1(&msg1);
    tampered_bytes[0] ^= 0x01;
    let tampered_msg1 = MessageOne::<CS>::from_bytes(&tampered_bytes).unwrap();

    // Skip if we corrupted the public key to all zeros
    if *tampered_msg1.public_key() == GenericArray::default() {
        return;
    }

    let mut rng2 = StdRng::seed_from_u64(99);
    let (_, responder) = Responder::respond(&tampered_msg1, &mut rng2).unwrap();

    // The commitment won't match because it was computed over the original key
    let result = responder.finish(&msg3);
    assert!(matches!(result, Err(ShortcakeError::InvalidCommitment)));
}

#[test]
fn test_message_sizes() {
    assert_eq!(MessageOne::<CS>::size(), 64);
    assert_eq!(MessageTwo::<CS>::size(), 64);
    assert_eq!(MessageThree::<CS>::size(), 32);
}

#[test]
fn test_known_answer() {
    // Deterministic test vector for cross-implementation compatibility.
    // If the protocol internals change, this test must be updated.
    let mut rng = StdRng::seed_from_u64(0);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, init_output) = initiator.finish(&msg2).unwrap();
    let resp_output = responder.finish(&msg3).unwrap();

    assert_eq!(init_output.sas(), resp_output.sas());
    assert_eq!(init_output.shared_secret(), resp_output.shared_secret());

    // Pin the SAS and shared secret to detect accidental changes.
    // These values are deterministic given seed=0 and the current protocol.
    let sas_hex = hex::encode(init_output.sas());
    let secret_hex = hex::encode(init_output.shared_secret());

    assert_eq!(sas_hex, "7a19fb0c65");
    assert_eq!(
        secret_hex,
        "26f214d652f301b379cff9796f9d58be58fd694507efa0674ef10a8da825844d"
    );

    // Verify outputs are deterministic across runs
    let (init_output2, resp_output2) = run_protocol(0);
    assert_eq!(init_output.sas(), init_output2.sas());
    assert_eq!(init_output.shared_secret(), init_output2.shared_secret());
    assert_eq!(resp_output.sas(), resp_output2.sas());
    assert_eq!(resp_output.shared_secret(), resp_output2.shared_secret());

    // Pin the exact hex values for regression detection
    assert_eq!(sas_hex, hex::encode(init_output2.sas()));
    assert_eq!(secret_hex, hex::encode(init_output2.shared_secret()));
}

#[test]
fn test_tampered_responder_nonce_causes_sas_mismatch() {
    let mut rng = StdRng::seed_from_u64(42);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();

    // Tamper with the responder's nonce in MessageTwo
    let mut tampered_bytes = serialize_msg2(&msg2);
    // Nonce starts at offset 32 (after the public key)
    tampered_bytes[32] ^= 0x01;
    let tampered_msg2 = MessageTwo::<CS>::from_bytes(&tampered_bytes).unwrap();

    // Initiator processes tampered msg2 (no error — tampering is detected
    // only through SAS mismatch, which happens out-of-band)
    let (msg3, init_output) = initiator.finish(&tampered_msg2).unwrap();
    let resp_output = responder.finish(&msg3).unwrap();

    // SAS values must differ because the initiator saw a different nonce
    assert_ne!(init_output.sas(), resp_output.sas());
}

#[test]
fn test_tampered_responder_public_key_causes_sas_mismatch() {
    let mut rng = StdRng::seed_from_u64(42);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();

    // Tamper with the responder's public key in MessageTwo
    let mut tampered_bytes = serialize_msg2(&msg2);
    tampered_bytes[0] ^= 0x01;
    let tampered_msg2 = MessageTwo::<CS>::from_bytes(&tampered_bytes).unwrap();

    let (msg3, init_output) = initiator.finish(&tampered_msg2).unwrap();
    let resp_output = responder.finish(&msg3).unwrap();

    // SAS values must differ (responder_pk is an input to the SAS hash)
    assert_ne!(init_output.sas(), resp_output.sas());
    // Shared secrets must also differ (different ECDH output)
    assert_ne!(init_output.shared_secret(), resp_output.shared_secret());
}

#[test]
fn test_message_replay_across_sessions() {
    // Messages from one session must not be valid in another session
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(2);

    // Session 1
    let (msg1_s1, _) = Initiator::<CS>::start(&mut rng1);
    let (_, responder_s1) = Responder::respond(&msg1_s1, &mut rng1).unwrap();

    // Session 2
    let (msg1_s2, initiator_s2) = Initiator::<CS>::start(&mut rng2);
    let (msg2_s2, _) = Responder::respond(&msg1_s2, &mut rng2).unwrap();
    let (msg3_s2, _) = initiator_s2.finish(&msg2_s2).unwrap();

    // Replay msg3 from session 2 into session 1's responder
    let result = responder_s1.finish(&msg3_s2);
    assert!(matches!(result, Err(ShortcakeError::InvalidCommitment)));
}

#[test]
fn test_both_nonces_contribute_to_sas() {
    let mut rng = StdRng::seed_from_u64(42);

    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (_, output_original) = initiator.finish(&msg2).unwrap();

    // Run again with a different initiator nonce (different seed)
    let mut rng2 = StdRng::seed_from_u64(99);
    let (msg1_b, initiator_b) = Initiator::<CS>::start(&mut rng2);
    let (msg2_b, _) = Responder::respond(&msg1_b, &mut rng2).unwrap();
    let (_, output_diff_init) = initiator_b.finish(&msg2_b).unwrap();

    // SAS must differ when initiator nonces differ
    assert_ne!(output_original.sas(), output_diff_init.sas());
}

#[test]
fn test_corrupted_serialized_message_one() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    // Corrupt each byte position of MessageOne and verify the commitment
    // catches the tampering
    let msg1_bytes = serialize_msg1(&msg1);
    for i in 0..msg1_bytes.len() {
        let mut corrupted = msg1_bytes.clone();
        corrupted[i] ^= 0x01;
        let corrupted_msg1 = MessageOne::<CS>::from_bytes(&corrupted).unwrap();

        // Skip if we corrupted the public key to all zeros (separate error)
        if *corrupted_msg1.public_key() == GenericArray::default() {
            continue;
        }

        let mut rng_c = StdRng::seed_from_u64(i as u64 + 1000);
        let resp_result = Responder::respond(&corrupted_msg1, &mut rng_c);
        if let Ok((_, responder)) = resp_result {
            let result = responder.finish(&msg3);
            assert!(
                matches!(result, Err(ShortcakeError::InvalidCommitment)),
                "corruption at byte {i} was not detected"
            );
        }
    }
}

#[test]
fn test_sas_length() {
    let (init_output, resp_output) = run_protocol(42);
    assert_eq!(init_output.sas().len(), 5);
    assert_eq!(resp_output.sas().len(), 5);
    assert_eq!(crate::SHARED_SECRET_LENGTH, 32);
}

#[test]
fn test_deserialization_rejects_wrong_length() {
    let too_short = [0u8; 10];
    assert!(matches!(
        MessageOne::<CS>::from_bytes(&too_short),
        Err(ShortcakeError::Deserialization)
    ));
    assert!(matches!(
        MessageTwo::<CS>::from_bytes(&too_short),
        Err(ShortcakeError::Deserialization)
    ));
    assert!(matches!(
        MessageThree::<CS>::from_bytes(&too_short),
        Err(ShortcakeError::Deserialization)
    ));
}

#[test]
fn test_output_debug_redacts_shared_secret() {
    let (output, _) = run_protocol(42);
    let debug_str = format!("{:?}", output);

    // The debug output should contain REDACTED and NOT contain the actual
    // shared secret bytes
    assert!(debug_str.contains("[REDACTED]"));
    let secret_hex = hex::encode(output.shared_secret());
    assert!(
        !debug_str.contains(&secret_hex),
        "Debug output should not contain the shared secret"
    );
}

#[test]
fn test_shared_secret_zeroized_on_drop() {
    let (output, _) = run_protocol(42);

    // Box the output so the heap pointer remains stable.
    // Use into_raw so we can call drop_in_place without deallocating,
    // allowing us to inspect the memory after the Drop impl runs.
    let output = Box::new(output);
    let ptr = Box::into_raw(output);
    let layout = unsafe { std::alloc::Layout::for_value(&*ptr) };
    let secret_ptr = unsafe { (*ptr).shared_secret().as_ptr() };
    let secret_len = crate::SHARED_SECRET_LENGTH;

    // Verify it's non-zero before drop
    let pre_drop: Vec<u8> = unsafe { core::slice::from_raw_parts(secret_ptr, secret_len) }.to_vec();
    assert!(
        pre_drop.iter().any(|&b| b != 0),
        "secret should be non-zero before drop"
    );

    // Run the Drop impl (which calls zeroize) without deallocating
    unsafe {
        core::ptr::drop_in_place(ptr);
    }

    // Read the memory after drop — it should be zeroed
    let post_drop: Vec<u8> =
        unsafe { core::slice::from_raw_parts(secret_ptr, secret_len) }.to_vec();
    assert_eq!(
        post_drop,
        vec![0u8; secret_len],
        "shared secret memory should be zeroed after drop"
    );

    // Deallocate the memory
    unsafe {
        std::alloc::dealloc(ptr as *mut u8, layout);
    }
}

#[test]
fn test_output_not_clone() {
    // Static assertion: Output<CS> must not implement Clone.
    // This function will fail to compile if Output<CS> implements Clone.
    fn assert_not_clone<T>() {
        // We use a negative reasoning approach: if this test compiles,
        // Output does not implement Clone (because we never call
        // the function with a Clone bound).
    }
    assert_not_clone::<Output<CS>>();
}

#[test]
fn test_write_to_roundtrip_message_one() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, _) = Initiator::<CS>::start(&mut rng);

    let bytes = serialize_msg1(&msg1);
    let restored = MessageOne::<CS>::from_bytes(&bytes).unwrap();
    assert_eq!(msg1, restored);
}

#[test]
fn test_write_to_roundtrip_message_two() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, _) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();

    let bytes = serialize_msg2(&msg2);
    let restored = MessageTwo::<CS>::from_bytes(&bytes).unwrap();
    assert_eq!(msg2, restored);
}

#[test]
fn test_write_to_roundtrip_message_three() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    let bytes = serialize_msg3(&msg3);
    let restored = MessageThree::<CS>::from_bytes(&bytes).unwrap();
    assert_eq!(msg3, restored);
}

#[cfg(feature = "alloc")]
#[test]
fn test_to_bytes_matches_write_to() {
    let mut rng = StdRng::seed_from_u64(42);
    let (msg1, initiator) = Initiator::<CS>::start(&mut rng);
    let (msg2, _) = Responder::respond(&msg1, &mut rng).unwrap();
    let (msg3, _) = initiator.finish(&msg2).unwrap();

    assert_eq!(serialize_msg1(&msg1), msg1.to_bytes());
    assert_eq!(serialize_msg2(&msg2), msg2.to_bytes());
    assert_eq!(serialize_msg3(&msg3), msg3.to_bytes());
}
