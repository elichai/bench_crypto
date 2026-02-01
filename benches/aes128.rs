use aes::Aes128;
use bench_crypto::{SEED, SIZES};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{Rng, RngExt, SeedableRng, rngs::SmallRng};
use std::hint::black_box;

fn bench_aes128(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES128");

    let max_size = *SIZES.iter().max().unwrap();
    let mut data = vec![0u8; max_size];

    let mut rng = SmallRng::seed_from_u64(SEED);
    for size in SIZES {
        group.throughput(Throughput::Bytes(*size as u64));

        // RustCrypto - AES128 Encrypt
        group.bench_with_input(
            BenchmarkId::new("RustCrypto/encrypt", size),
            size,
            |b, &size| {
                let key: [u8; 16] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());
                let cipher = Aes128::new(&key.into());
                let mut data: Vec<_> = data
                    .chunks_exact(16)
                    .map(|chunk| chunk.try_into().unwrap())
                    .collect();

                b.iter(|| {
                    cipher.encrypt_blocks(black_box(&mut data));
                });
            },
        );

        // RustCrypto - AES128 Decrypt
        group.bench_with_input(
            BenchmarkId::new("RustCrypto/decrypt", size),
            size,
            |b, &size| {
                let key: [u8; 16] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());

                let cipher = Aes128::new(&key.into());
                let mut data: Vec<_> = data
                    .chunks_exact(16)
                    .map(|chunk| chunk.try_into().unwrap())
                    .collect();

                b.iter(|| {
                    cipher.decrypt_blocks(black_box(&mut data));
                });
            },
        );

        // AWS-LC-RS - AES128 ECB Encrypt
        group.bench_with_input(
            BenchmarkId::new("AWS-LC-RS/encrypt", size),
            size,
            |b, &size| {
                use aws_lc_rs::cipher::{AES_128, EncryptingKey, UnboundCipherKey};

                let key: [u8; 16] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());

                let unbound_key = UnboundCipherKey::new(&AES_128, &key).unwrap();
                let encrypting_key = EncryptingKey::ecb(unbound_key).unwrap();

                b.iter(|| {
                    let _ctx = encrypting_key.encrypt(black_box(&mut data)).unwrap();
                });
            },
        );

        // AWS-LC-RS - AES128 ECB Decrypt
        group.bench_with_input(
            BenchmarkId::new("AWS-LC-RS/decrypt", size),
            size,
            |b, &size| {
                use aws_lc_rs::cipher::{
                    AES_128, DecryptingKey, DecryptionContext, UnboundCipherKey,
                };

                let key: [u8; 16] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());

                b.iter(|| {
                    let unbound_key = UnboundCipherKey::new(&AES_128, &key).unwrap();
                    let decrypting_key = DecryptingKey::ecb(unbound_key).unwrap();
                    let mut data_copy = data.clone();
                    decrypting_key
                        .decrypt(black_box(&mut data_copy), DecryptionContext::None)
                        .unwrap();
                });
            },
        );

        // Note: Ring doesn't expose raw AES128 encryption (only AEAD modes)

        // OpenSSL - AES128 Encrypt
        group.bench_with_input(
            BenchmarkId::new("OpenSSL/encrypt", size),
            size,
            |b, &size| {
                use openssl::symm::{Cipher, encrypt};

                let key: [u8; 16] = rng.random();
                let iv: [u8; 16] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());

                b.iter(|| {
                    let ciphertext =
                        encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), black_box(&data)).unwrap();
                    black_box(ciphertext);
                });
            },
        );

        // OpenSSL - AES128 Decrypt
        group.bench_with_input(
            BenchmarkId::new("OpenSSL/decrypt", size),
            size,
            |b, &size| {
                use openssl::symm::{Cipher, decrypt, encrypt};

                let key: [u8; 16] = rng.random();
                let iv: [u8; 16] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());
                let ciphertext = encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), &data).unwrap();

                b.iter(|| {
                    let plaintext = decrypt(
                        Cipher::aes_128_cbc(),
                        &key,
                        Some(&iv),
                        black_box(&ciphertext),
                    )
                    .unwrap();
                    black_box(plaintext);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_aes128);
criterion_main!(benches);
