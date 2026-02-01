use bench_crypto::SEED;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{RngExt, SeedableRng, rngs::SmallRng};
use std::hint::black_box;

fn bench_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519");

    let mut rng = SmallRng::seed_from_u64(SEED);

    // ed25519-dalek
    group.bench_function("ed25519-dalek Sign", |b| {
        use ed25519_dalek::{Signer, SigningKey};

        let seed_bytes: [u8; 32] = rng.random();
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let mut sig = [42; 64];

        b.iter(|| {
            sig = signing_key.sign(black_box(sig.as_slice())).to_bytes();
        })
    });

    group.bench_function("ed25519-dalek Verify", |b| {
        use ed25519_dalek::{Signer, SigningKey, Verifier};

        let seed_bytes: [u8; 32] = rng.random();
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let message: &[u8] = b"test message for signing";
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();

        b.iter(|| {
            verifying_key
                .verify(black_box(message), black_box(&signature))
                .unwrap();
        })
    });

    // Ring
    group.bench_function("Ring Sign", |b| {
        use ring::rand::SystemRandom;
        use ring::signature::{self};

        let rng = SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let mut sig = key_pair.sign(&[]);

        b.iter(|| {
            sig = key_pair.sign(black_box(sig.as_ref()));
        })
    });

    group.bench_function("Ring Verify", |b| {
        use ring::rand::SystemRandom;
        use ring::signature::{self, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let message: &[u8] = b"test message for signing";
        let sig = key_pair.sign(message);
        let peer_public_key_bytes = key_pair.public_key().as_ref();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            black_box(peer_public_key_bytes),
        );

        b.iter(|| {
            peer_public_key
                .verify(black_box(message), black_box(sig.as_ref()))
                .unwrap();
        })
    });

    // AWS-LC-RS
    group.bench_function("AWS-LC-RS Sign", |b| {
        use aws_lc_rs::signature::{self};

        let key_pair = signature::Ed25519KeyPair::generate().unwrap();
        let mut sig = key_pair.sign(&[]);

        b.iter(|| {
            sig = key_pair.sign(black_box(sig.as_ref()));
        })
    });

    group.bench_function("AWS-LC-RS Verify", |b| {
        use aws_lc_rs::signature::{self, KeyPair};

        let key_pair = signature::Ed25519KeyPair::generate().unwrap();
        let message: &[u8] = b"test message for signing";
        let sig = key_pair.sign(message);
        let peer_public_key_bytes = key_pair.public_key().as_ref();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            black_box(peer_public_key_bytes),
        );

        b.iter(|| {
            peer_public_key
                .verify(black_box(message), black_box(sig.as_ref()))
                .unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_ed25519);
criterion_main!(benches);
