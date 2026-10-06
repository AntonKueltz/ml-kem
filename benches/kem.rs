use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use mlkem::kem::{Kem, MlKem512, MlKem768, MlKem1024};

fn bench_kem(c: &mut Criterion) {
    // 512
    c.bench_function(&format!("keygen/512"), |b| b.iter(|| MlKem512::key_gen()));

    let (ek, dk) = MlKem512::key_gen();
    c.bench_function(&format!("encaps/512"), |b| {
        b.iter(|| MlKem512::encaps(black_box(&ek)))
    });

    let (_, ct) = MlKem512::encaps(&ek);
    c.bench_function(&format!("decaps/512"), |b| {
        b.iter(|| MlKem512::decaps(black_box(&dk), black_box(&ct)))
    });

    // 768
    c.bench_function(&format!("keygen/768"), |b| b.iter(|| MlKem768::key_gen()));

    let (ek, dk) = MlKem768::key_gen();
    c.bench_function(&format!("encaps/768"), |b| {
        b.iter(|| MlKem768::encaps(black_box(&ek)))
    });

    let (_, ct) = MlKem768::encaps(&ek);
    c.bench_function(&format!("decaps/768"), |b| {
        b.iter(|| MlKem768::decaps(black_box(&dk), black_box(&ct)))
    });

    // 1024
    c.bench_function(&format!("keygen/1024"), |b| b.iter(|| MlKem1024::key_gen()));

    let (ek, dk) = MlKem1024::key_gen();
    c.bench_function(&format!("encaps/1024"), |b| {
        b.iter(|| MlKem1024::encaps(black_box(&ek)))
    });

    let (_, ct) = MlKem1024::encaps(&ek);
    c.bench_function(&format!("decaps/1024"), |b| {
        b.iter(|| MlKem1024::decaps(black_box(&dk), black_box(&ct)))
    });
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
