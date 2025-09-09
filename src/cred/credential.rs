use anyhow::Result;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2_ecdsa::curve::curve_types::AffinePoint;
use plonky2_ecdsa::curve::curve_types::{Curve, CurveScalar};
#[allow(unused_imports)]
use plonky2_ecdsa::curve::ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

use crate::utils::parsing::hash_to_scalar;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CredentialData {
    pub cred_pk_sec1_compressed: String,
    pub delegation_level: u8,
    pub name: String,
    pub address: String,
    pub birthdate: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedECDSACredential {
    pub credential: CredentialData,
    pub cred_hash: Secp256K1Scalar,
    pub cred_sk: ECDSASecretKey<Secp256K1>,
    pub cred_pk: ECDSAPublicKey<Secp256K1>,
    pub signature: ECDSASignature<Secp256K1>,
}

#[derive(Serialize, Deserialize)]
pub struct IssuerKeypair {
    pub sk: ECDSASecretKey<Secp256K1>,
    pub pk: ECDSAPublicKey<Secp256K1>,
}

impl CredentialData {
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let credential_json: serde_json::Value = serde_json::to_value(self)?;
        Ok(credential_json)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let credential_json: serde_json::Value = serde_json::to_value(self)?;
        let cred_bytes = serde_json::to_vec(&credential_json)?;
        Ok(cred_bytes)
    }
}

/// Generate issuer keypair: (secret, public)
pub fn generate_issuer_keypair() -> IssuerKeypair {
    let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
    IssuerKeypair { sk, pk }
}

/// Generates a fixed-issued credential for "Dax Dustermann" for testing purposes.
pub fn issue_fixed_dummy_credential(
    issuer_sk: &ECDSASecretKey<Secp256K1>,
) -> Result<SignedECDSACredential> {
    let cred_sk_hex = "a4cd2bdcbf30c77205fca6f3873ff19b8a60f74eac38c0c259eb6ef880a9a5da";
    let cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_str_radix(cred_sk_hex, 16)?));
    let cred_pk = ECDSAPublicKey((CurveScalar(cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let cred_data = CredentialData {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&cred_pk),
        delegation_level: 0,
        name: "Dax Dustermann".to_string(),
        address: "Karolinenplatz 5, 64289 Darmstadt".to_string(),
        birthdate: "1990-01-01".to_string(),
    };

    let cred_json = cred_data.to_json_bytes()?;
    let cred_hash = hash_to_scalar(&cred_json)?;
    let signature = sign_message(cred_hash, *issuer_sk);

    Ok(SignedECDSACredential {
        credential: cred_data,
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

/// Issue a credential with its own keypair and user-provided attributes, signed by issuer_sk.
pub fn issue_credential(
    issuer_sk: &ECDSASecretKey<Secp256K1>,
    delegation_level: u8,
    name: String,
    address: String,
    birthdate: String,
) -> Result<SignedECDSACredential> {
    let cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let cred_pk =
        ECDSAPublicKey((CurveScalar(cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let credential = CredentialData {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&cred_pk),
        delegation_level,
        name,
        address,
        birthdate,
    };

    let cred_json = credential.to_json_bytes()?;
    let cred_hash = hash_to_scalar(&cred_json)?;
    let signature = sign_message(cred_hash, *issuer_sk);

    Ok(SignedECDSACredential {
        credential,
        cred_hash,
        cred_sk,
        cred_pk,
        signature,
    })
}
// Derive a delegated credential from a base credential
pub fn delegate_credential(base_credential: &SignedECDSACredential) -> Result<SignedECDSACredential> {
    let next_cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let next_cred_pk =
        ECDSAPublicKey((CurveScalar(next_cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let next_delegation_level = base_credential.credential.delegation_level + 1;

    let credential = CredentialData {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&next_cred_pk),
        delegation_level: next_delegation_level,
        name: base_credential.credential.name.clone(),
        address: base_credential.credential.address.clone(),
        birthdate: base_credential.credential.birthdate.clone(),
    };

    let cred_json = credential.to_json_bytes()?;
    let cred_hash = hash_to_scalar(&cred_json)?;
    let signature = sign_message(cred_hash, base_credential.cred_sk);

    Ok(SignedECDSACredential {
        credential,
        cred_hash,
        cred_sk: next_cred_sk,
        cred_pk: next_cred_pk,
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


#[test]
fn test_issue_credential_fixed() -> Result<()> {
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

#[test]
fn test_issue_credential_random() -> Result<()> {
    // Produce issuer keys and an issued credential + signature
    let kp = generate_issuer_keypair();
    let issued = issue_credential(&kp.sk, 0, "Bernd the Bread".to_string(), "Mürbeweg 3".to_string(), "too old".to_string())?;

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

#[test]
fn test_delegate_credential() -> Result<()> {
    let kp = generate_fixed_issuer_keypair();
    let issued = issue_fixed_dummy_credential(&kp.sk)?;
    let delegated = delegate_credential(&issued)?;
    println!("Delegated credential JSON: {}", serde_json::to_string_pretty(&delegated.credential)?);

    let is_valid = verify_message(delegated.cred_hash, delegated.signature, issued.cred_pk);
    assert!(is_valid, "issuer signature should verify");

    Ok(())
}


