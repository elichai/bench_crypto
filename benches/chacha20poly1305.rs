use bench_crypto::{SEED, SIZES};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{Rng, RngExt, SeedableRng, rngs::SmallRng};
use std::hint::black_box;

fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20Poly1305");
    let mut rng = SmallRng::seed_from_u64(SEED);

    let max_size = *SIZES.iter().max().unwrap();
    let mut data = vec![0u8; max_size];

    for size in SIZES {
        group.throughput(Throughput::Bytes(*size as u64));

        // RustCrypto - ChaCha20Poly1305 Encrypt
        group.bench_with_input(
            BenchmarkId::new("RustCrypto/encrypt", size),
            size,
            |b, &size| {
                use chacha20poly1305::ChaCha20Poly1305;
                use chacha20poly1305::aead::{AeadInOut, KeyInit};

                let key: [u8; 32] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());
                let cipher = ChaCha20Poly1305::new(&key.into());
                let mut tag = cipher
                    .encrypt_inout_detached(&[0; 12].into(), &[], data.as_mut_slice().into())
                    .unwrap();

                b.iter(|| {
                    let (nonce, _) = tag.split();
                    tag = cipher
                        .encrypt_inout_detached(
                            black_box(&nonce),
                            black_box(&[]),
                            black_box(data.as_mut_slice()).into(),
                        )
                        .unwrap();
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/decrypt", size),
            size,
            |b, &size| {
                use chacha20poly1305::ChaCha20Poly1305;
                use chacha20poly1305::aead::{AeadInOut, KeyInit};

                let key: [u8; 32] = rng.random();
                let nonce: [u8; 12] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());
                let cipher = ChaCha20Poly1305::new(&key.into());

                let tag = cipher
                    .encrypt_inout_detached(&nonce.into(), &[], data.as_mut_slice().into())
                    .unwrap();

                let mut work_buffer = data.clone();

                b.iter(|| {
                    work_buffer.copy_from_slice(&data);
                    cipher
                        .decrypt_inout_detached(
                            black_box(&nonce.into()),
                            black_box(&[]),
                            black_box(work_buffer.as_mut_slice()).into(),
                            black_box(&tag),
                        )
                        .unwrap();
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("AWS-LC-RS/encrypt", size),
            size,
            |b, &size| {
                use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

                let key: [u8; 32] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
                let less_safe_key = LessSafeKey::new(unbound_key);

                let mut tag = less_safe_key
                    .seal_in_place_separate_tag(
                        Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap(),
                        Aad::empty(),
                        data.as_mut_slice(),
                    )
                    .unwrap();

                b.iter(|| {
                    let (nonce, _) = tag.as_ref().split_at(12);
                    let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
                    tag = less_safe_key
                        .seal_in_place_separate_tag(
                            nonce,
                            black_box(Aad::empty()),
                            black_box(data.as_mut_slice()),
                        )
                        .unwrap();
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("AWS-LC-RS/decrypt", size),
            size,
            |b, &size| {
                use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

                let key: [u8; 32] = rng.random();
                let nonce: [u8; 12] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
                let less_safe_key = LessSafeKey::new(unbound_key);

                let tag = less_safe_key
                    .seal_in_place_separate_tag(
                        Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                        Aad::empty(),
                        data.as_mut_slice(),
                    )
                    .unwrap();

                let mut work_buffer = data.clone();

                b.iter(|| {
                    less_safe_key
                        .open_separate_gather(
                            black_box(Nonce::try_assume_unique_for_key(&nonce).unwrap()),
                            black_box(Aad::empty()),
                            black_box(&data),
                            black_box(tag.as_ref()),
                            work_buffer.as_mut_slice(),
                        )
                        .unwrap()
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("Ring/encrypt", size), size, |b, &size| {
            use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

            let key: [u8; 32] = rng.random();
            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());
            let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
            let less_safe_key = LessSafeKey::new(unbound_key);
            let mut tag = less_safe_key
                .seal_in_place_separate_tag(
                    Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap(),
                    Aad::empty(),
                    data.as_mut_slice(),
                )
                .unwrap();

            b.iter(|| {
                let (nonce, _) = tag.as_ref().split_at(12);
                let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
                tag = less_safe_key
                    .seal_in_place_separate_tag(
                        nonce,
                        black_box(Aad::empty()),
                        black_box(data.as_mut_slice()),
                    )
                    .unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("Ring/decrypt", size), size, |b, &size| {
            use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

            let key: [u8; 32] = rng.random();
            let nonce: [u8; 12] = rng.random();
            data.resize(size, 0);
            rng.fill_bytes(data.as_mut_slice());
            let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
            let less_safe_key = LessSafeKey::new(unbound_key);

            let tag = less_safe_key
                .seal_in_place_separate_tag(
                    Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                    Aad::empty(),
                    data.as_mut_slice(),
                )
                .unwrap();

            let mut work_buffer = data.clone();

            b.iter(|| {
                work_buffer.copy_from_slice(&data);
                less_safe_key
                    .open_in_place_separate_tag(
                        black_box(Nonce::try_assume_unique_for_key(&nonce).unwrap()),
                        black_box(Aad::empty()),
                        black_box(tag),
                        black_box(work_buffer.as_mut_slice()),
                        0..,
                    )
                    .unwrap();
            });
        });

        group.bench_with_input(
            BenchmarkId::new("OpenSSL/encrypt", size),
            size,
            |b, &size| {
                let key: [u8; 32] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());

                let mut working_buf = vec![0u8; size];
                let mut tag = openssl_encrypt_aead(&key, &[0u8; 12], &[], &data, &mut working_buf);

                b.iter(|| {
                    let (nonce, _) = tag.split_at(12);
                    tag = openssl_encrypt_aead(
                        black_box(&key),
                        black_box(nonce),
                        black_box(&[]),
                        black_box(&data),
                        black_box(&mut working_buf),
                    );
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("OpenSSL/decrypt", size),
            size,
            |b, &size| {
                let key: [u8; 32] = rng.random();
                let nonce: [u8; 12] = rng.random();
                data.resize(size, 0);
                rng.fill_bytes(data.as_mut_slice());

                let mut working_buf = data.clone();
                let tag = openssl_encrypt_aead(&key, &nonce, &[], &working_buf, &mut data);
                b.iter(|| {
                    openssl_decrypt_aead(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&[]),
                        black_box(&data),
                        black_box(&tag),
                        black_box(&mut working_buf),
                    );
                });
            },
        );
    }

    group.finish();
}

fn openssl_encrypt_aead(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> [u8; 16] {
    use openssl::symm::{Cipher, Crypter};

    assert_eq!(ciphertext.len(), plaintext.len());
    let mut encrypter = Crypter::new(
        Cipher::chacha20_poly1305(),
        openssl::symm::Mode::Encrypt,
        key,
        Some(iv),
    )
    .unwrap();
    encrypter.aad_update(aad).unwrap();
    let mut count = encrypter.update(plaintext, ciphertext).unwrap();
    assert_eq!(count, plaintext.len());
    count = encrypter.finalize(&mut ciphertext[count..]).unwrap();
    assert_eq!(count, 0);
    let mut tag = [0u8; 16];
    encrypter.get_tag(&mut tag).unwrap();
    tag
}

fn openssl_decrypt_aead(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext: &mut [u8],
) {
    use openssl::symm::{Cipher, Crypter};
    // assert_eq!(plaintext.len(), ciphertext.len());
    let mut decrypter = Crypter::new(
        Cipher::chacha20_poly1305(),
        openssl::symm::Mode::Decrypt,
        key,
        Some(iv),
    )
    .unwrap();
    decrypter.aad_update(aad).unwrap();
    let count = decrypter.update(ciphertext, plaintext).unwrap();
    assert_eq!(count, ciphertext.len());
    decrypter.set_tag(tag).unwrap();
    let count = decrypter.finalize(&mut plaintext[count..]).unwrap();
    assert_eq!(count, 0);
}

criterion_group!(benches, bench_chacha20poly1305);
criterion_main!(benches);
