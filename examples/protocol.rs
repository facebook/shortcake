// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Full 3-move SAS protocol demo using the X25519-SHA256 ciphersuite.
//!
//! Each protocol message is serialized to bytes and deserialized before being
//! passed to the next step, simulating an over-the-wire exchange.
//!
//! Run with:
//! ```sh
//! cargo run --example protocol --features x25519-sha256
//! ```

use shortcake::{
    Initiator, Responder, X25519Ciphertext, X25519DecapsulationKey, X25519EncapsulationKey,
    X25519Sha256,
};

fn main() {
    let mut rng = rand::thread_rng();

    // Step 0: Initiator generates a KEM keypair.
    let dk = X25519DecapsulationKey::generate(&mut rng);
    let ek = dk.encapsulation_key();
    println!("Initiator generated X25519 keypair");

    // ── Move 1: Initiator -> Responder ──────────────────────────────────

    let (initiator_state, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);

    // Serialize for transmission.
    let ek_bytes = msg1.ek.to_bytes();
    let commitment_bytes: [u8; 32] = msg1.commitment.into();
    println!(
        "\nMove 1 ({} bytes):",
        ek_bytes.len() + commitment_bytes.len()
    );
    println!("  ek:         {:02x?}", ek_bytes);
    println!("  commitment: {:02x?}", commitment_bytes);

    // Deserialize on the Responder side.
    let ek = X25519EncapsulationKey::from_bytes(ek_bytes);
    let commitment = commitment_bytes.into();

    // ── Move 2: Responder -> Initiator ──────────────────────────────────

    let (responder_state, msg2) = Responder::<X25519Sha256>::start(&mut rng, ek, commitment)
        .expect("Responder failed to start");

    // Serialize for transmission.
    let ct_bytes = msg2.ct.to_bytes();
    let responder_nonce = msg2.responder_nonce;
    println!(
        "\nMove 2 ({} bytes):",
        ct_bytes.len() + responder_nonce.len()
    );
    println!("  ct:              {:02x?}", ct_bytes);
    println!("  responder_nonce: {:02x?}", responder_nonce);

    // Deserialize on the Initiator side.
    let ct = X25519Ciphertext::from_bytes(ct_bytes);

    // ── Move 3: Initiator -> Responder ──────────────────────────────────

    let (initiator_confirm, msg3) = initiator_state
        .handle_responder_response(ct, responder_nonce)
        .expect("Initiator failed to handle response");

    // Serialize for transmission.
    let initiator_nonce = msg3.initiator_nonce;
    println!("\nMove 3 ({} bytes):", initiator_nonce.len());
    println!("  initiator_nonce: {:02x?}", initiator_nonce);

    // ── Commitment verification & SAS comparison ────────────────────────

    let responder_confirm = responder_state
        .handle_initiator_nonce(initiator_nonce)
        .expect("Responder commitment verification failed");
    println!("\nResponder verified commitment successfully");

    let initiator_sas = initiator_confirm.sas();
    let responder_sas = responder_confirm.sas();
    println!("Initiator SAS: {:?}", initiator_sas);
    println!("Responder SAS: {:?}", responder_sas);
    assert_eq!(
        initiator_sas.as_bytes(),
        responder_sas.as_bytes(),
        "SAS mismatch!"
    );
    println!("SAS values match — user would confirm out-of-band");

    // ── Key derivation ──────────────────────────────────────────────────

    let mut initiator_key = [0u8; 32];
    let mut responder_key = [0u8; 32];
    initiator_confirm
        .finalize(b"example-salt", b"example-info", &mut initiator_key)
        .expect("Initiator key derivation failed");
    responder_confirm
        .finalize(b"example-salt", b"example-info", &mut responder_key)
        .expect("Responder key derivation failed");

    println!("\nInitiator key: {:02x?}", initiator_key);
    println!("Responder key: {:02x?}", responder_key);
    assert_eq!(initiator_key, responder_key, "Derived keys do not match!");
    println!("\nShared keys match — protocol complete!");
}
