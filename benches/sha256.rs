use bench_crypto::{SEED, SIZES};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::hint::black_box;

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA256");
    let mut rng = SmallRng::seed_from_u64(SEED);
    let max_size = *SIZES.iter().max().unwrap();
    let mut data = vec![0u8; max_size];

    for size in SIZES {
        group.throughput(Throughput::Bytes(*size as u64));

        // RustCrypto - SHA256
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, &size| {
            use sha2::{Digest, Sha256};

            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());

            b.iter(|| {
                let mut hasher = Sha256::new();
                hasher.update(black_box(&data));
                let result = hasher.finalize();
                black_box(result);
            });
        });

        // AWS-LC-RS - SHA256
        group.bench_with_input(BenchmarkId::new("AWS-LC-RS", size), size, |b, &size| {
            use aws_lc_rs::digest;

            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());

            b.iter(|| {
                let digest = digest::digest(&digest::SHA256, black_box(&data));
                black_box(digest);
            });
        });

        // Ring - SHA256
        group.bench_with_input(BenchmarkId::new("Ring", size), size, |b, &size| {
            use ring::digest;

            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());

            b.iter(|| {
                let digest = digest::digest(&digest::SHA256, black_box(&data));
                black_box(digest);
            });
        });

        // OpenSSL - SHA256
        group.bench_with_input(BenchmarkId::new("OpenSSL", size), size, |b, &size| {
            use openssl::hash::{MessageDigest, hash};

            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());

            b.iter(|| {
                let digest = hash(MessageDigest::sha256(), black_box(&data)).unwrap();
                black_box(digest);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
