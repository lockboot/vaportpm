//! Isolated EC benchmarks for comparing P-256 and P-384 performance
//!
//! These tests measure cycle counts for single ECDSA signature verifications
//! to isolate EC performance from other factors (JSON parsing, X.509, etc.)

use risc0_zkvm::{default_executor, ExecutorEnv};
use vaportpm_zk_methods::EC_BENCH_GUEST_ELF;

/// P-256 test vector - valid ECDSA P-256 signature
mod p256_test_vector {
    use hex_literal::hex;

    // Public key in uncompressed SEC1 format (0x04 || x || y)
    pub const PUBLIC_KEY: [u8; 65] = hex!(
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    );

    // SHA-256 hash of the message "sample"
    pub const MESSAGE_HASH: [u8; 32] = hex!(
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    );

    // ECDSA signature (r || s) in fixed-size format
    pub const SIGNATURE: [u8; 64] = hex!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    );
}

/// P-384 test vector - valid ECDSA P-384 signature
mod p384_test_vector {
    use hex_literal::hex;

    // Public key in uncompressed SEC1 format (0x04 || x || y)
    pub const PUBLIC_KEY: [u8; 97] = hex!(
        "043e80bb19d6500788aaadfab3970aa5c39e75d79bf8dc81e823d4908301a6ffb0"
        "ee8fc6e4c76cf03d46a7a379769815c90d23c1bcdbcf4dd37f434f05ae9c524c"
        "7f7219c3deaa778eefe3e8e620da823c2670cb023321ce851322bbd1c44932aa"
    );

    // SHA-256 hash of the message "sample" (same as P-256 for fair comparison)
    pub const MESSAGE_HASH: [u8; 32] = hex!(
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    );

    // ECDSA signature (r || s) in fixed-size format
    pub const SIGNATURE: [u8; 96] = hex!(
        "d4bc0c427c75dcbfa66c3a7f09a54465d43f69d7978ee454d8abf022621f585a"
        "70535448bb1e50647009b6ef6f818400efaa015e183dc460bc456057c555ac95"
        "27f34cbbbf325986e463531910176a988c4b3468727172d614ccdcade0ae89df"
    );
}

#[test]
fn test_p256_ecdsa_cycles() {
    let bench_type: u8 = 0; // P-256
    let pubkey = p256_test_vector::PUBLIC_KEY.to_vec();
    let message_hash = p256_test_vector::MESSAGE_HASH;
    let signature = p256_test_vector::SIGNATURE.to_vec();

    let env = ExecutorEnv::builder()
        .write(&bench_type)
        .unwrap()
        .write(&pubkey)
        .unwrap()
        .write(&message_hash)
        .unwrap()
        .write(&signature)
        .unwrap()
        .build()
        .unwrap();

    let executor = default_executor();
    let session = executor.execute(env, EC_BENCH_GUEST_ELF).unwrap();

    // Verify the signature was valid
    let result: bool = session.journal.decode().unwrap();
    assert!(result, "P-256 signature verification should succeed");

    println!();
    println!("=== P-256 ECDSA Verification ===");
    println!("Total cycles: {}", session.cycles());
    println!("Segments: {}", session.segments.len());
    println!();
}

#[test]
fn test_p384_ecdsa_cycles() {
    let bench_type: u8 = 1; // P-384
    let pubkey = p384_test_vector::PUBLIC_KEY.to_vec();
    let message_hash = p384_test_vector::MESSAGE_HASH;
    let signature = p384_test_vector::SIGNATURE.to_vec();

    let env = ExecutorEnv::builder()
        .write(&bench_type)
        .unwrap()
        .write(&pubkey)
        .unwrap()
        .write(&message_hash)
        .unwrap()
        .write(&signature)
        .unwrap()
        .build()
        .unwrap();

    let executor = default_executor();
    let session = executor.execute(env, EC_BENCH_GUEST_ELF).unwrap();

    // Verify the signature was valid
    let result: bool = session.journal.decode().unwrap();
    assert!(result, "P-384 signature verification should succeed");

    println!();
    println!("=== P-384 ECDSA Verification ===");
    println!("Total cycles: {}", session.cycles());
    println!("Segments: {}", session.segments.len());
    println!();
}

/// Run both benchmarks and print comparison
#[test]
fn test_ec_comparison() {
    // P-256
    let p256_cycles = {
        let bench_type: u8 = 0;
        let pubkey = p256_test_vector::PUBLIC_KEY.to_vec();
        let message_hash = p256_test_vector::MESSAGE_HASH;
        let signature = p256_test_vector::SIGNATURE.to_vec();

        let env = ExecutorEnv::builder()
            .write(&bench_type)
            .unwrap()
            .write(&pubkey)
            .unwrap()
            .write(&message_hash)
            .unwrap()
            .write(&signature)
            .unwrap()
            .build()
            .unwrap();

        let executor = default_executor();
        let session = executor.execute(env, EC_BENCH_GUEST_ELF).unwrap();

        let result: bool = session.journal.decode().unwrap();
        assert!(result, "P-256 signature verification should succeed");

        session.cycles()
    };

    // P-384
    let p384_cycles = {
        let bench_type: u8 = 1;
        let pubkey = p384_test_vector::PUBLIC_KEY.to_vec();
        let message_hash = p384_test_vector::MESSAGE_HASH;
        let signature = p384_test_vector::SIGNATURE.to_vec();

        let env = ExecutorEnv::builder()
            .write(&bench_type)
            .unwrap()
            .write(&pubkey)
            .unwrap()
            .write(&message_hash)
            .unwrap()
            .write(&signature)
            .unwrap()
            .build()
            .unwrap();

        let executor = default_executor();
        let session = executor.execute(env, EC_BENCH_GUEST_ELF).unwrap();

        let result: bool = session.journal.decode().unwrap();
        assert!(result, "P-384 signature verification should succeed");

        session.cycles()
    };

    println!();
    println!("=== EC Performance Comparison ===");
    println!("P-256 ECDSA verify: {} cycles", p256_cycles);
    println!("P-384 ECDSA verify: {} cycles", p384_cycles);
    println!("Ratio (P-384/P-256): {:.2}x", p384_cycles as f64 / p256_cycles as f64);
    println!();
    println!("Expected ratio: 1.5-2.0x (due to larger field size)");
    println!();
}
