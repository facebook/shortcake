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
    use shortcake::{Initiator, Responder, X25519Sha256};

    pub fn bench_initiator_start(c: &mut Criterion) {
        c.bench_function("x25519/initiator_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter(|| Initiator::<X25519Sha256>::start(&mut rng));
        });
    }

    pub fn bench_responder_start(c: &mut Criterion) {
        c.bench_function("x25519/responder_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (_, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
                    msg1
                },
                |msg1| {
                    let mut rng = rand::thread_rng();
                    Responder::<X25519Sha256>::start(&mut rng, msg1)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_initiator_finish(c: &mut Criterion) {
        c.bench_function("x25519/initiator_finish", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (state, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
                    let (_, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1).unwrap();
                    (state, msg2)
                },
                |(state, msg2)| state.finish(msg2),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_responder_finish(c: &mut Criterion) {
        c.bench_function("x25519/responder_finish", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (istate, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
                    let (rstate, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1).unwrap();
                    let (_, msg3) = istate.finish(msg2).unwrap();
                    (rstate, msg3)
                },
                |(rstate, msg3)| rstate.finish(msg3),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_verify(c: &mut Criterion) {
        c.bench_function("x25519/verify", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (istate, msg1) = Initiator::<X25519Sha256>::start(&mut rng);
                    let (rstate, msg2) = Responder::<X25519Sha256>::start(&mut rng, msg1).unwrap();
                    let (i_code, msg3) = istate.finish(msg2).unwrap();
                    let r_code = rstate.finish(msg3).unwrap();
                    let r_code_bytes = r_code.as_bytes().to_vec();
                    // Drop r_code so it doesn't count in the benchmark
                    drop(r_code);
                    (i_code, r_code_bytes)
                },
                |(i_code, r_code_bytes)| i_code.verify(&r_code_bytes),
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

#[cfg(feature = "mlkem768-sha256")]
mod mlkem_benches {
    use criterion::Criterion;
    use shortcake::{Initiator, MlKem768Sha256, Responder};

    pub fn bench_initiator_start(c: &mut Criterion) {
        c.bench_function("mlkem768/initiator_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter(|| Initiator::<MlKem768Sha256>::start(&mut rng));
        });
    }

    pub fn bench_responder_start(c: &mut Criterion) {
        c.bench_function("mlkem768/responder_start", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (_, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng);
                    msg1
                },
                |msg1| {
                    let mut rng = rand::thread_rng();
                    Responder::<MlKem768Sha256>::start(&mut rng, msg1)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_initiator_finish(c: &mut Criterion) {
        c.bench_function("mlkem768/initiator_finish", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (state, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng);
                    let (_, msg2) = Responder::<MlKem768Sha256>::start(&mut rng, msg1).unwrap();
                    (state, msg2)
                },
                |(state, msg2)| state.finish(msg2),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_responder_finish(c: &mut Criterion) {
        c.bench_function("mlkem768/responder_finish", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (istate, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng);
                    let (rstate, msg2) =
                        Responder::<MlKem768Sha256>::start(&mut rng, msg1).unwrap();
                    let (_, msg3) = istate.finish(msg2).unwrap();
                    (rstate, msg3)
                },
                |(rstate, msg3)| rstate.finish(msg3),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_verify(c: &mut Criterion) {
        c.bench_function("mlkem768/verify", |b| {
            let mut rng = rand::thread_rng();
            b.iter_batched(
                || {
                    let (istate, msg1) = Initiator::<MlKem768Sha256>::start(&mut rng);
                    let (rstate, msg2) =
                        Responder::<MlKem768Sha256>::start(&mut rng, msg1).unwrap();
                    let (i_code, msg3) = istate.finish(msg2).unwrap();
                    let r_code = rstate.finish(msg3).unwrap();
                    let r_code_bytes = r_code.as_bytes().to_vec();
                    drop(r_code);
                    (i_code, r_code_bytes)
                },
                |(i_code, r_code_bytes)| i_code.verify(&r_code_bytes),
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

#[cfg(all(feature = "x25519-sha256", feature = "mlkem768-sha256"))]
criterion_group!(
    benches,
    x25519_benches::bench_initiator_start,
    x25519_benches::bench_responder_start,
    x25519_benches::bench_initiator_finish,
    x25519_benches::bench_responder_finish,
    x25519_benches::bench_verify,
    mlkem_benches::bench_initiator_start,
    mlkem_benches::bench_responder_start,
    mlkem_benches::bench_initiator_finish,
    mlkem_benches::bench_responder_finish,
    mlkem_benches::bench_verify,
);

#[cfg(all(feature = "x25519-sha256", not(feature = "mlkem768-sha256")))]
criterion_group!(
    benches,
    x25519_benches::bench_initiator_start,
    x25519_benches::bench_responder_start,
    x25519_benches::bench_initiator_finish,
    x25519_benches::bench_responder_finish,
    x25519_benches::bench_verify,
);

#[cfg(all(feature = "mlkem768-sha256", not(feature = "x25519-sha256")))]
criterion_group!(
    benches,
    mlkem_benches::bench_initiator_start,
    mlkem_benches::bench_responder_start,
    mlkem_benches::bench_initiator_finish,
    mlkem_benches::bench_responder_finish,
    mlkem_benches::bench_verify,
);

#[cfg(not(any(feature = "x25519-sha256", feature = "mlkem768-sha256")))]
mod noop {
    use criterion::Criterion;
    pub fn bench_noop(_c: &mut Criterion) {}
}

#[cfg(not(any(feature = "x25519-sha256", feature = "mlkem768-sha256")))]
criterion_group!(benches, noop::bench_noop);

criterion_main!(benches);
