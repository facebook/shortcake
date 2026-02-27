// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use criterion::{criterion_group, criterion_main, Criterion};
use shortcake::{Initiator, Responder, X25519DecapsulationKey, X25519Sha256};

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let dk = X25519DecapsulationKey::generate(&mut rng);
            dk.encapsulation_key()
        });
    });
}

fn bench_initiator_start(c: &mut Criterion) {
    c.bench_function("initiator_start", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let dk = X25519DecapsulationKey::generate(&mut rng);
            let ek = dk.encapsulation_key();
            Initiator::<X25519Sha256>::start(&mut rng, ek, dk)
        });
    });
}

fn bench_responder_start(c: &mut Criterion) {
    c.bench_function("responder_start", |b| {
        let mut rng = rand::thread_rng();
        b.iter_batched(
            || {
                let dk = X25519DecapsulationKey::generate(&mut rng);
                let ek = dk.encapsulation_key();
                let (_, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                msg1
            },
            |msg1| {
                let mut rng = rand::thread_rng();
                Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_handle_response(c: &mut Criterion) {
    c.bench_function("handle_response", |b| {
        let mut rng = rand::thread_rng();
        b.iter_batched(
            || {
                let dk = X25519DecapsulationKey::generate(&mut rng);
                let ek = dk.encapsulation_key();
                let (state, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                let (_, msg2) =
                    Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
                (state, msg2)
            },
            |(state, msg2)| state.handle_responder_response(msg2.ct, msg2.responder_nonce),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_verify_commitment(c: &mut Criterion) {
    c.bench_function("verify_commitment", |b| {
        let mut rng = rand::thread_rng();
        b.iter_batched(
            || {
                let dk = X25519DecapsulationKey::generate(&mut rng);
                let ek = dk.encapsulation_key();
                let (istate, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                let (rstate, msg2) =
                    Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
                let (_, msg3) = istate
                    .handle_responder_response(msg2.ct, msg2.responder_nonce)
                    .unwrap();
                (rstate, msg3)
            },
            |(rstate, msg3)| rstate.handle_initiator_nonce(msg3.initiator_nonce),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_finalize(c: &mut Criterion) {
    c.bench_function("finalize", |b| {
        let mut rng = rand::thread_rng();
        b.iter_batched(
            || {
                let dk = X25519DecapsulationKey::generate(&mut rng);
                let ek = dk.encapsulation_key();
                let (istate, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                let (_, msg2) =
                    Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment).unwrap();
                let (confirm, _) = istate
                    .handle_responder_response(msg2.ct, msg2.responder_nonce)
                    .unwrap();
                confirm
            },
            |confirm| {
                let mut key = [0u8; 32];
                confirm
                    .finalize(b"bench-salt", b"bench-info", &mut key)
                    .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_initiator_start,
    bench_responder_start,
    bench_handle_response,
    bench_verify_commitment,
    bench_finalize,
);
criterion_main!(benches);
