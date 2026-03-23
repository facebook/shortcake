// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use criterion::{criterion_group, criterion_main};

#[cfg(feature = "xwing")]
mod xwing_benches {
    use criterion::Criterion;
    use rand_core::UnwrapErr;
    use shortcake::{Initiator, Responder, XWingSha3};

    fn test_rng() -> UnwrapErr<getrandom::SysRng> {
        UnwrapErr(getrandom::SysRng)
    }

    pub fn bench_initiator_start(c: &mut Criterion) {
        c.bench_function("xwing/initiator_start", |b| {
            let mut rng = test_rng();
            b.iter(|| Initiator::<XWingSha3>::start(&mut rng));
        });
    }

    pub fn bench_responder_start(c: &mut Criterion) {
        c.bench_function("xwing/responder_start", |b| {
            let mut rng = test_rng();
            b.iter_batched(
                || {
                    let (_, msg1) = Initiator::<XWingSha3>::start(&mut rng);
                    msg1
                },
                |msg1| {
                    let mut rng = test_rng();
                    Responder::<XWingSha3>::start(&mut rng, msg1)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_initiator_finish(c: &mut Criterion) {
        c.bench_function("xwing/initiator_finish", |b| {
            let mut rng = test_rng();
            b.iter_batched(
                || {
                    let (state, msg1) = Initiator::<XWingSha3>::start(&mut rng);
                    let (_, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
                    (state, msg2)
                },
                |(state, msg2)| state.finish(msg2),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_responder_finish(c: &mut Criterion) {
        c.bench_function("xwing/responder_finish", |b| {
            let mut rng = test_rng();
            b.iter_batched(
                || {
                    let (istate, msg1) = Initiator::<XWingSha3>::start(&mut rng);
                    let (rstate, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
                    let (_, msg3) = istate.finish(msg2).unwrap();
                    (rstate, msg3)
                },
                |(rstate, msg3)| rstate.finish(msg3),
                criterion::BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_verify(c: &mut Criterion) {
        c.bench_function("xwing/verify", |b| {
            let mut rng = test_rng();
            b.iter_batched(
                || {
                    let (istate, msg1) = Initiator::<XWingSha3>::start(&mut rng);
                    let (rstate, msg2) = Responder::<XWingSha3>::start(&mut rng, msg1).unwrap();
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

#[cfg(feature = "xwing")]
criterion_group!(
    benches,
    xwing_benches::bench_initiator_start,
    xwing_benches::bench_responder_start,
    xwing_benches::bench_initiator_finish,
    xwing_benches::bench_responder_finish,
    xwing_benches::bench_verify,
);

#[cfg(not(feature = "xwing"))]
mod noop {
    use criterion::Criterion;
    pub fn bench_noop(_c: &mut Criterion) {}
}

#[cfg(not(feature = "xwing"))]
criterion_group!(benches, noop::bench_noop);

criterion_main!(benches);
