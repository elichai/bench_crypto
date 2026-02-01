use bench_crypto::{SEED, SIZES};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{Rng, RngExt, SeedableRng, rngs::SmallRng};
use std::hint::black_box;

fn bench_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20");
    let mut rng = SmallRng::seed_from_u64(SEED);
    let max_size = *SIZES.iter().max().unwrap();
    let mut data = vec![0u8; max_size];

    for size in SIZES {
        group.throughput(Throughput::Bytes(*size as u64));

        // RustCrypto - ChaCha20
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, &size| {
            use chacha20::ChaCha20;
            use chacha20::cipher::{KeyIvInit, StreamCipher};

            let key: [u8; 32] = rng.random();
            let nonce: [u8; 12] = rng.random();
            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());

            b.iter(|| {
                let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
                cipher.apply_keystream(black_box(&mut data));
            });
        });

        // Note: AWS-LC-RS and Ring don't expose raw ChaCha20 (only ChaCha20-Poly1305 AEAD)
        // They are included in the ChaCha20Poly1305 benchmarks

        // OpenSSL - ChaCha20
        group.bench_with_input(BenchmarkId::new("OpenSSL", size), size, |b, &size| {
            use openssl::symm::{Cipher, encrypt};

            let key: [u8; 32] = rng.random();
            let iv: [u8; 16] = rng.random();
            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());

            b.iter(|| {
                let ciphertext =
                    encrypt(Cipher::chacha20(), &key, Some(&iv), black_box(&data)).unwrap();
                black_box(ciphertext);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_chacha20);
criterion_main!(benches);
