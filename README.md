# Cryptographic Library Benchmarks

This project benchmarks various cryptographic operations across multiple Rust cryptography libraries.

## Libraries Tested

1. **RustCrypto** - Pure Rust implementations (aes, chacha20, chacha20poly1305, sha2)
2. **AWS-LC-RS** - AWS's cryptographic library using AWS-LC
3. **Ring** - A safe, fast crypto library (ChaCha20Poly1305 and SHA256 only)
4. **OpenSSL** - Bindings to OpenSSL

## Algorithms Benchmarked

1. **AES-128** - Raw AES-128 encryption/decryption (ECB mode for AWS-LC-RS, CBC for OpenSSL, block-level for RustCrypto)
2. **ChaCha20** - Stream cipher (RustCrypto and OpenSSL only - AWS-LC-RS and Ring don't expose raw ChaCha20)
3. **ChaCha20-Poly1305** - Authenticated encryption (AEAD)
4. **SHA-256** - Cryptographic hash function

## Running Benchmarks

Run all benchmarks:
```bash
cargo bench
```

Run specific benchmark:
```bash
cargo bench aes128
cargo bench chacha20
cargo bench chacha20poly1305
cargo bench sha256
```

## Benchmark Sizes

Each benchmark tests three different data sizes:
- 1 KB (1,024 bytes)
- 16 KB (16,384 bytes)
- 1 MB (1,048,576 bytes)

## Results

Results will be saved in `target/criterion/` directory. Criterion will generate:
- HTML reports in `target/criterion/*/report/index.html`
- Performance statistics
- Comparison with previous runs

## Notes

- **AES-128**: Ring doesn't expose raw AES operations (only AEAD modes like AES-GCM)
- **ChaCha20**: AWS-LC-RS and Ring don't expose raw ChaCha20 (only ChaCha20-Poly1305 AEAD)
- **Performance**: Results will vary based on CPU features (AES-NI, AVX2, NEON, etc.)
- **Security**: ECB mode (used for AWS-LC-RS AES) is NOT secure for general use - it's only used here for benchmarking raw AES performance

## Building

Requires:
- Rust (latest stable)
- C compiler (for aws-lc-rs and openssl)
- OpenSSL development libraries (for openssl crate)

On macOS with Homebrew:
```bash
brew install openssl@3
```

On Debian/Ubuntu:
```bash
sudo apt-get install pkg-config libssl-dev
```

Then build:
```bash
cargo build --benches
```
