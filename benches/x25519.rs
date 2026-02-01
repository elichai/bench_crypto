use bench_crypto::SEED;
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{RngExt, SeedableRng, rngs::SmallRng};
use std::hint::black_box;

fn bench_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519");

    let mut rng = SmallRng::seed_from_u64(SEED);
    // x25519-dalek
    group.bench_function("x25519-dalek", |b| {
        use x25519_dalek::x25519;

        let alice_bytes: [u8; 32] = rng.random();
        let bob_bytes: [u8; 32] = rng.random();

        let mut shared_secret = bob_bytes;
        b.iter(|| {
            shared_secret = black_box(x25519(black_box(alice_bytes), black_box(shared_secret)));
        })
    });

    // Ring
    group.bench_function("Ring", |b| {
        use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
        use ring::rand::SystemRandom;

        let rng = SystemRandom::new();
        let bob_private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let bob_public_bytes = bob_private.compute_public_key().unwrap();
        let bob_public = UnparsedPublicKey::new(&X25519, black_box(&bob_public_bytes));

        b.iter(|| {
            let alice_private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();

            agree_ephemeral(alice_private, &bob_public, |k| {
                black_box(k);
            })
            .unwrap();
        });
    });

    // AWS-LC-RS
    group.bench_function("AWS-LC-RS", |b| {
        use aws_lc_rs::agreement::{PrivateKey, UnparsedPublicKey, X25519, agree};

        let bob_private = PrivateKey::generate(&X25519).unwrap();
        let bob_public_bytes = bob_private.compute_public_key().unwrap();
        let alice_private = PrivateKey::generate(&X25519).unwrap();
        let bob_public = UnparsedPublicKey::new(&X25519, black_box(&bob_public_bytes));

        b.iter(|| {
            agree(
                &alice_private,
                bob_public,
                aws_lc_rs::error::Unspecified,
                |k| {
                    black_box(k);
                    Ok(())
                },
            )
            .unwrap();
        });
    });

    // OpenSSL
    group.bench_function("OpenSSL", |b| {
        use openssl::derive::Deriver;
        use openssl::pkey::{Id, PKey};

        let alice_private = PKey::generate_x25519().unwrap();

        let bob_private = PKey::generate_x25519().unwrap();
        let bob_public_bytes = bob_private.raw_public_key().unwrap();
        let bob_public = PKey::public_key_from_raw_bytes(&bob_public_bytes, Id::X25519).unwrap();
        let mut deriver = Deriver::new(&alice_private).unwrap();

        b.iter(|| {
            deriver.set_peer(black_box(&bob_public)).unwrap();
            let secret = deriver.derive_to_vec().unwrap();
            black_box(secret);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_x25519);
criterion_main!(benches);
