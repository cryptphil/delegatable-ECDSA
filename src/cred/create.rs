use anyhow::Result;
use hex::{FromHex, ToHex};
use k256::{
    ecdsa::{signature::DigestSigner, signature::DigestVerifier, Signature, SigningKey, VerifyingKey},
    PublicKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub struct Credential {
    pub cred_pubkey_hex: String,
    pub L: u8,
    pub Name: String,
}

pub struct IssuedCredential {
    pub credential: Credential,
    pub cred_sk_hex: String,
    pub cred_pk: PublicKey,
    pub signature_der_hex: String,
}

/// Generate issuer keypair: (secret, public)
pub fn generate_issuer_keypair() -> (SigningKey, PublicKey) {
    let sk = SigningKey::random(&mut OsRng);
    // Convert owned VerifyingKey -> PublicKey
    let pk: PublicKey = sk.verifying_key().into();
    (sk, pk)
}

/// Issue a credential with its own keypair and attributes, signed by issuer_sk.
pub fn issue_credential(issuer_sk: &SigningKey) -> Result<IssuedCredential> {
    // Credential keypair
    let cred_sk = SigningKey::random(&mut OsRng);
    let cred_vk: VerifyingKey = *cred_sk.verifying_key();
    let cred_pk: PublicKey = cred_vk.into(); // VerifyingKey -> PublicKey
    let cred_pubkey_bytes = cred_pk.to_encoded_point(true).as_bytes().to_vec();

    // Payload
    let cred = Credential {
        cred_pubkey_hex: cred_pubkey_bytes.encode_hex::<String>(),
        L: 0,
        Name: "Alice".to_string(),
    };

    // Serialize and sign with issuer SK
    let cred_bytes = serde_json::to_vec(&cred)?;
    let sig: Signature = issuer_sk.sign_digest(Sha256::new().chain_update(&cred_bytes));

    // Sanity verify using issuer VK
    let issuer_vk: VerifyingKey = *issuer_sk.verifying_key();
    issuer_vk.verify_digest(Sha256::new().chain_update(&cred_bytes), &sig)?;

    Ok(IssuedCredential {
        credential: cred,
        cred_sk_hex: cred_sk.to_bytes().encode_hex::<String>(),
        cred_pk,
        signature_der_hex: sig.to_der().as_bytes().encode_hex::<String>(),
    })
}

#[test]
fn test_issue_credential() -> Result<()> {
    // Produce issuer keys and an issued credential + signature
    let (issuer_sk, issuer_pk) = generate_issuer_keypair();
    let issued = issue_credential(&issuer_sk)?;

    println!(
        "Issuer PK (compressed): {}",
        issuer_pk
            .to_encoded_point(true)
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "Credential JSON: {}",
        serde_json::to_string_pretty(&issued.credential)?
    );
    println!("Signature (DER hex): {}", issued.signature_der_hex);

    // --- Reconstruct what was signed ---
    let cred_bytes = serde_json::to_vec(&issued.credential)?;

    // --- Parse DER signature from hex ---
    let sig_der = Vec::from_hex(&issued.signature_der_hex)?;
    let sig = Signature::from_der(&sig_der)?;

    // --- Convert issuer PublicKey -> VerifyingKey ---
    // Use SEC1 bytes so this works across k256 versions.
    let issuer_vk = VerifyingKey::from_sec1_bytes(
        issuer_pk.to_encoded_point(true).as_bytes()
    )?;

    // --- Verify ---
    issuer_vk
        .verify_digest(Sha256::new().chain_update(&cred_bytes), &sig)
        .expect("issuer signature should verify");

    Ok(())
}