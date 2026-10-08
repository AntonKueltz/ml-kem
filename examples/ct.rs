use dudect_bencher::rand::{Rng, RngExt};
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};

use mlkem::kem::{Kem, MlKem768};

const N: usize = 100_000;

fn decaps_valid_vs_invalid_ctxt(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (ek, dk) = MlKem768::key_gen();
    let (_k, valid_c) = MlKem768::encaps(&ek);

    let mut inputs = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);

    for _ in 0..N {
        if rng.random::<bool>() {
            inputs.push(valid_c);
            classes.push(Class::Left);
        } else {
            let mut c = [0u8; 1088];
            rng.fill_bytes(&mut c);
            inputs.push(c);
            classes.push(Class::Right);
        }
    }

    for (c, class) in inputs.iter().zip(classes) {
        runner.run_one(class, || MlKem768::decaps(&dk, c));
    }
}

fn decaps_ctxt_off_by_one(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (ek, dk) = MlKem768::key_gen();
    let (_k, valid_c) = MlKem768::encaps(&ek);

    let mut inputs = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);

    for i in 0..N {
        if rng.random::<bool>() {
            inputs.push(valid_c);
            classes.push(Class::Left);
        } else {
            let mut c = valid_c;
            c[i % 1088] ^= 0x01;
            inputs.push(c);
            classes.push(Class::Right);
        }
    }

    for (c, class) in inputs.iter().zip(classes) {
        runner.run_one(class, || MlKem768::decaps(&dk, c));
    }
}

fn decaps_valid_vs_invalid_dk(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);

    for _ in 0..N {
        let (ek, dk) = MlKem768::key_gen();
        let (_, c) = MlKem768::encaps(&ek);

        if rng.random::<bool>() {
            inputs.push((dk, c));
            classes.push(Class::Left);
        } else {
            let (_, dk_rand) = MlKem768::key_gen();
            inputs.push((dk_rand, c));
            classes.push(Class::Right);
        }
    }

    for ((dk, c), class) in inputs.iter().zip(classes) {
        runner.run_one(class, || MlKem768::decaps(&dk, &c));
    }
}

ctbench_main!(
    decaps_valid_vs_invalid_ctxt,
    decaps_ctxt_off_by_one,
    decaps_valid_vs_invalid_dk
);
