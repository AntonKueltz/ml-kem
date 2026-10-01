use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use mlkem::kem::KEM;

fn bench_kem(c: &mut Criterion) {
    for (name, mut kem) in [
        ("512", KEM::ml_kem_512()),
        ("768", KEM::ml_kem_768()),
        ("1024", KEM::ml_kem_1024()),
    ] {
        c.bench_function(&format!("keygen/{name}"), |b| b.iter(|| kem.key_gen()));

        let (ek, dk) = kem.key_gen();
        c.bench_function(&format!("encaps/{name}"), |b| {
            b.iter(|| kem.encaps(black_box(&ek)))
        });

        let (_, ct) = kem.encaps(&ek);
        c.bench_function(&format!("decaps/{name}"), |b| {
            b.iter(|| kem.decaps(black_box(&dk), black_box(&ct)))
        });
    }
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
