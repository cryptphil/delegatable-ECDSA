use anyhow::Result;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2_ecdsa::curve::curve_types::AffinePoint;
use plonky2_ecdsa::curve::curve_types::{Curve, CurveScalar};
use plonky2_ecdsa::curve::ecdsa::{
    sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature,
};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub cred_pk_sec1_compressed: String,
    pub delegation_level: u8,
    pub name: String,
    pub address: String,
    pub birthdate: String,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct IssuedEcdsaCredential {
    pub credential: Credential,
    pub cred_hash: Secp256K1Scalar,
    pub cred_sk: ECDSASecretKey<Secp256K1>,
    pub cred_pk: ECDSAPublicKey<Secp256K1>,
    pub signature: ECDSASignature<Secp256K1>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct IssuerKeypair {
    pub sk: ECDSASecretKey<Secp256K1>,
    pub pk: ECDSAPublicKey<Secp256K1>,
}

#[allow(dead_code)]
/// Generate issuer keypair: (secret, public)
pub fn generate_issuer_keypair() -> IssuerKeypair {
    let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
    IssuerKeypair { sk, pk }
}

#[allow(dead_code)]
/// Generates a fixed-issued credential for "Dax Dustermann" for testing purposes.
pub fn issue_fixed_dummy_credential(
    issuer_sk: &ECDSASecretKey<Secp256K1>,
) -> Result<IssuedEcdsaCredential> {
    let cred_sk_hex = "a4cd2bdcbf30c77205fca6f3873ff19b8a60f74eac38c0c259eb6ef880a9a5da";
    let cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_str_radix(cred_sk_hex, 16)?));
    let cred_pk = ECDSAPublicKey((CurveScalar(cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let credential = Credential {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&cred_pk),
        delegation_level: 0,
        name: "Dax Dustermann".to_string(),
        address: "Karolinenplatz 5, 64289 Darmstadt".to_string(),
        birthdate: "1990-01-01".to_string(),
    };

    let cred_hash = hash_credential_to_scalar(&credential)?;
    let signature = sign_message(cred_hash, *issuer_sk);

    Ok(IssuedEcdsaCredential {
        credential,
        cred_hash,
        cred_sk,
        cred_pk,
        signature,
    })
}

// Generates a fixed issuer keypair for testing purposes.
pub fn generate_fixed_issuer_keypair() -> IssuerKeypair {
    let sk_hex = "53f053f57615a8ecb9afe430fc3ee292d6d0d4f1a1cb870d1dbdb51162a880a0";
    let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_str_radix(sk_hex, 16).unwrap()));
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
    IssuerKeypair { sk, pk }
}

#[allow(dead_code)]
/// Issue a credential with its own keypair and user-provided attributes, signed by issuer_sk.
pub fn issue_credential(
    issuer_sk: &ECDSASecretKey<Secp256K1>,
    delegation_level: u8,
    name: String,
    address: String,
    birthdate: String,
) -> Result<IssuedEcdsaCredential> {
    let cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let cred_pk =
        ECDSAPublicKey((CurveScalar(cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let credential = Credential {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&cred_pk),
        delegation_level,
        name,
        address,
        birthdate,
    };

    let cred_hash = hash_credential_to_scalar(&credential)?;
    let signature = sign_message(cred_hash, *issuer_sk);

    Ok(IssuedEcdsaCredential {
        credential,
        cred_hash,
        cred_sk,
        cred_pk,
        signature,
    })
}

pub(crate) fn compressed_pubkey_hex(pk: &ECDSAPublicKey<Secp256K1>) -> String {
    let point: AffinePoint<Secp256K1> = pk.0.clone();

    let x_big: BigUint = point.x.to_canonical_biguint();
    let y_big: BigUint = point.y.to_canonical_biguint();

    let mut x_bytes = x_big.to_bytes_be();
    if x_bytes.len() < 32 {
        let mut tmp = vec![0u8; 32 - x_bytes.len()];
        tmp.extend_from_slice(&x_bytes);
        x_bytes = tmp;
    }

    let prefix = if &y_big % 2u8 == 0u8.into() {
        0x02
    } else {
        0x03
    }; // "is even?"

    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(&x_bytes);

    hex::encode(compressed)
}

fn hash_credential_to_scalar<T: serde::Serialize>(
    credential: &T,
) -> anyhow::Result<Secp256K1Scalar> {
    let cred_bytes = serde_json::to_vec(credential)?;
    let digest = Sha256::digest(&cred_bytes); // 32 bytes

    // Convert into [u64; 4] (big-endian order)
    let mut limbs = [0u64; 4];
    for (i, chunk) in digest.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    Ok(Secp256K1Scalar(limbs))
}

#[test]
fn test_issue_credential() -> Result<()> {
    // Produce issuer keys and an issued credential + signature
    let kp = generate_fixed_issuer_keypair();
    let issued = issue_fixed_dummy_credential(&kp.sk)?;

    // Pretty-print some basics
    println!("Issuer PK (compressed): {}", compressed_pubkey_hex(&kp.pk));
    println!(
        "Credential JSON: {}",
        serde_json::to_string_pretty(&issued.credential)?
    );

    // Verify using Plonky2 ECDSA primitives over secp256k1
    let is_valid = verify_message(issued.cred_hash, issued.signature, kp.pk);
    assert!(is_valid, "issuer signature should verify");

    Ok(())
}


