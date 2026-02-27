// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use criterion::{criterion_group, criterion_main};

#[cfg(feature = "x25519-sha256")]
mod x25519_benches {
    use criterion::Criterion;
    use shortcake::{Initiator, Responder, X25519DecapsulationKey, X25519Sha256};

    pub fn bench_keygen(c: &mut Criterion) {
        c.bench_function("x25519/keygen", |b| {
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let dk = X25519DecapsulationKey::generate(&mut rng);
                dk.encapsulation_key()
            });
        });
    }

    pub fn bench_initiator_start(c: &mut Criterion) {
        c.bench_function("x25519/initiator_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let dk = X25519DecapsulationKey::generate(&mut rng);
                let ek = dk.encapsulation_key();
                Initiator::<X25519Sha256>::start(&mut rng, ek, dk)
            });
        });
    }

    pub fn bench_responder_start(c: &mut Criterion) {
        c.bench_function("x25519/responder_start", |b| {
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

    pub fn bench_handle_response(c: &mut Criterion) {
        c.bench_function("x25519/handle_response", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = X25519DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (state, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                    let (_, msg2) =
                        Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                            .unwrap();
                    (state, msg2)
                },
                |(state, msg2)| state.handle_responder_response(msg2.ct, msg2.responder_nonce),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_verify_commitment(c: &mut Criterion) {
        c.bench_function("x25519/verify_commitment", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = X25519DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (istate, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                    let (rstate, msg2) =
                        Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                            .unwrap();
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

    pub fn bench_finalize(c: &mut Criterion) {
        c.bench_function("x25519/finalize", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = X25519DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (istate, msg1) = Initiator::<X25519Sha256>::start(&mut rng, ek, dk);
                    let (_, msg2) =
                        Responder::<X25519Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                            .unwrap();
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
}

#[cfg(feature = "mlkem768-sha256")]
mod mlkem_benches {
    use criterion::Criterion;
    use shortcake::{Initiator, MlKem768DecapsulationKey, MlKem768Sha256, Responder};

    pub fn bench_keygen(c: &mut Criterion) {
        c.bench_function("mlkem768/keygen", |b| {
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let dk = MlKem768DecapsulationKey::generate(&mut rng);
                dk.encapsulation_key()
            });
        });
    }

    pub fn bench_initiator_start(c: &mut Criterion) {
        c.bench_function("mlkem768/initiator_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let dk = MlKem768DecapsulationKey::generate(&mut rng);
                let ek = dk.encapsulation_key();
                Initiator::<MlKem768Sha256>::start(&mut rng, ek, dk)
            });
        });
    }

    pub fn bench_responder_start(c: &mut Criterion) {
        c.bench_function("mlkem768/responder_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = MlKem768DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (_, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng, ek, dk);
                    msg1
                },
                |msg1| {
                    let mut rng = rand::thread_rng();
                    Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_handle_response(c: &mut Criterion) {
        c.bench_function("mlkem768/handle_response", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = MlKem768DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (state, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng, ek, dk);
                    let (_, msg2) =
                        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                            .unwrap();
                    (state, msg2)
                },
                |(state, msg2)| state.handle_responder_response(msg2.ct, msg2.responder_nonce),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_verify_commitment(c: &mut Criterion) {
        c.bench_function("mlkem768/verify_commitment", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = MlKem768DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (istate, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng, ek, dk);
                    let (rstate, msg2) =
                        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                            .unwrap();
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

    pub fn bench_finalize(c: &mut Criterion) {
        c.bench_function("mlkem768/finalize", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let dk = MlKem768DecapsulationKey::generate(&mut rng);
                    let ek = dk.encapsulation_key();
                    let (istate, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng, ek, dk);
                    let (_, msg2) =
                        Responder::<MlKem768Sha256>::start(&mut rng, msg1.ek, msg1.commitment)
                            .unwrap();
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
}

#[cfg(all(feature = "x25519-sha256", feature = "mlkem768-sha256"))]
criterion_group!(
    benches,
    x25519_benches::bench_keygen,
    x25519_benches::bench_initiator_start,
    x25519_benches::bench_responder_start,
    x25519_benches::bench_handle_response,
    x25519_benches::bench_verify_commitment,
    x25519_benches::bench_finalize,
    mlkem_benches::bench_keygen,
    mlkem_benches::bench_initiator_start,
    mlkem_benches::bench_responder_start,
    mlkem_benches::bench_handle_response,
    mlkem_benches::bench_verify_commitment,
    mlkem_benches::bench_finalize,
);

#[cfg(all(feature = "x25519-sha256", not(feature = "mlkem768-sha256")))]
criterion_group!(
    benches,
    x25519_benches::bench_keygen,
    x25519_benches::bench_initiator_start,
    x25519_benches::bench_responder_start,
    x25519_benches::bench_handle_response,
    x25519_benches::bench_verify_commitment,
    x25519_benches::bench_finalize,
);

#[cfg(all(feature = "mlkem768-sha256", not(feature = "x25519-sha256")))]
criterion_group!(
    benches,
    mlkem_benches::bench_keygen,
    mlkem_benches::bench_initiator_start,
    mlkem_benches::bench_responder_start,
    mlkem_benches::bench_handle_response,
    mlkem_benches::bench_verify_commitment,
    mlkem_benches::bench_finalize,
);

#[cfg(not(any(feature = "x25519-sha256", feature = "mlkem768-sha256")))]
mod noop {
    use criterion::Criterion;
    pub fn bench_noop(_c: &mut Criterion) {}
}

#[cfg(not(any(feature = "x25519-sha256", feature = "mlkem768-sha256")))]
criterion_group!(benches, noop::bench_noop);

criterion_main!(benches);
