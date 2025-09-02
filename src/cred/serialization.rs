use hex::{FromHex, ToHex};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::ecdsa::signature::digest::Digest;
use k256::ecdsa::signature::DigestVerifier;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use crate::cred::create::{generate_issuer_keypair, issue_dummy_credential, Credential, IssuedCredential};

#[derive(Serialize, Deserialize)]
struct IssuerKeypairJson {
    /// 32-byte secret key as hex (big-endian)
    pub sk_hex: String,
    /// Compressed SEC1-encoded public key as hex
    pub pk_sec1_compressed_hex: String,
}

#[derive(Serialize, Deserialize)]
struct IssuedCredentialJson {
    pub credential: Credential,
    /// 32-byte credential secret key as hex (big-endian)
    pub cred_sk_hex: String,
    /// Compressed SEC1-encoded credential public key as hex
    pub cred_pk_compressed_hex: String,
    /// Issuer signature over `credential` (DER-encoded ECDSA) as hex
    pub signature_hex: String,
}

#[allow(dead_code)]
/// Export only the issuer keypair to a JSON file.
/// Returns the file path written.
pub fn export_issuer_keypair_to_json(
    issuer_sk: &SigningKey,
    issuer_path: &str,
) -> anyhow::Result<String> {
    use std::fs;

    // Issuer keypair JSON view
    let issuer_pk: PublicKey = issuer_sk.verifying_key().into();
    let issuer_json = IssuerKeypairJson {
        sk_hex: issuer_sk.to_bytes().as_slice().encode_hex::<String>(),
        pk_sec1_compressed_hex: issuer_pk
            .to_encoded_point(true)
            .as_bytes()
            .encode_hex::<String>(),
    };

    let issuer_str = serde_json::to_string_pretty(&issuer_json)?;
    fs::write(issuer_path, issuer_str)?;
    Ok(issuer_path.to_string())
}

#[allow(dead_code)]
/// Export only the issued credential (including holder keypair and issuer signature) to a JSON file.
/// Returns the file path written.
pub fn export_issued_credential_to_json(
    issued: &IssuedCredential,
    issued_path: &str,
) -> anyhow::Result<String> {
    use std::fs;

    // Issued credential JSON view
    let issued_json = IssuedCredentialJson {
        credential: issued.credential.clone(),
        cred_sk_hex: issued.cred_sk.to_bytes().as_slice().encode_hex::<String>(),
        cred_pk_compressed_hex: issued
            .cred_pk
            .to_encoded_point(true)
            .as_bytes()
            .encode_hex::<String>(),
        signature_hex: issued.signature_hex.clone(),
    };

    let issued_str = serde_json::to_string_pretty(&issued_json)?;
    fs::write(issued_path, issued_str)?;
    Ok(issued_path.to_string())
}

#[allow(dead_code)]
/// Read issuer keypair from JSON file written by `export_issuer_and_issued_to_json`.
pub fn read_issuer_keypair_from_json(path: &str) -> anyhow::Result<(SigningKey, PublicKey)> {
    use std::fs;
    let data = fs::read_to_string(path)?;
    let parsed: IssuerKeypairJson = serde_json::from_str(&data)?;

    let sk_bytes_vec = Vec::from_hex(parsed.sk_hex)?;
    if sk_bytes_vec.len() != 32 {
        anyhow::bail!("issuer sk must be 32 bytes, got {}", sk_bytes_vec.len());
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&sk_bytes_vec);
    let issuer_sk = SigningKey::from_bytes(&sk_bytes.into())?;

    let pk_bytes = Vec::from_hex(parsed.pk_sec1_compressed_hex)?;
    let issuer_pk = PublicKey::from_sec1_bytes(&pk_bytes)?;

    Ok((issuer_sk, issuer_pk))
}

#[allow(dead_code)]
/// Read an issued credential from JSON file written by `export_issuer_and_issued_to_json`.
pub fn read_issued_credential_from_json(path: &str) -> anyhow::Result<IssuedCredential> {
    use std::fs;
    let data = fs::read_to_string(path)?;
    let parsed: IssuedCredentialJson = serde_json::from_str(&data)?;

    // Rebuild credential secret key
    let sk_bytes_vec = Vec::from_hex(parsed.cred_sk_hex)?;
    if sk_bytes_vec.len() != 32 {
        anyhow::bail!("credential sk must be 32 bytes, got {}", sk_bytes_vec.len());
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&sk_bytes_vec);
    let cred_sk = SigningKey::from_bytes(&sk_bytes.into())?;

    // Rebuild credential public key
    let pk_bytes = Vec::from_hex(parsed.cred_pk_compressed_hex)?;
    let cred_pk = PublicKey::from_sec1_bytes(&pk_bytes)?;

    Ok(IssuedCredential {
        credential: parsed.credential,
        cred_sk,
        cred_pk,
        signature_hex: parsed.signature_hex,
    })
}

#[test]
fn test_export_and_import_json_roundtrip() -> anyhow::Result<()> {
    use std::fs;

    // 1) Create issuer and issue a credential
    let (issuer_sk, issuer_pk) = generate_issuer_keypair();
    let issued = issue_dummy_credential(&issuer_sk)?;

    // 2) Export both to JSON files (relative to crate root)
    let issuer_path = "issuer_keypair.json";
    let issued_path = "issued_credential.json";
    let _ip = export_issuer_keypair_to_json(&issuer_sk, issuer_path)?;
    let _cp = export_issued_credential_to_json(&issued, issued_path)?;

    // 3) Read back
    let (issuer_sk2, issuer_pk2) = read_issuer_keypair_from_json(issuer_path)?;
    let issued2 = read_issued_credential_from_json(issued_path)?;

    // 4) Basic equality checks (public material)
    assert_eq!(
        issuer_pk.to_encoded_point(true).as_bytes(),
        issuer_pk2.to_encoded_point(true).as_bytes()
    );
    assert_eq!(
        issued.cred_pk.to_encoded_point(true).as_bytes(),
        issued2.cred_pk.to_encoded_point(true).as_bytes()
    );
    assert_eq!(issued.signature_hex, issued2.signature_hex);
    assert_eq!(issued.credential, issued2.credential);

    // 5) Verify the issuer signature still validates on the reloaded credential
    let cred_bytes = serde_json::to_vec(&issued2.credential)?;
    let sig_der = Vec::from_hex(&issued2.signature_hex)?;
    let sig = Signature::from_der(&sig_der)?;

    // Reconstruct a VerifyingKey from the reloaded issuer pk
    let issuer_vk = VerifyingKey::from_sec1_bytes(issuer_pk2.to_encoded_point(true).as_bytes())?;
    issuer_vk.verify_digest(Sha256::new().chain_update(&cred_bytes), &sig)?;

    // 6) Cleanup files so repeated `cargo test` runs stay tidy (ignore errors)
    let _ = fs::remove_file(issuer_path);
    let _ = fs::remove_file(issued_path);

    // Avoid unused variable warning
    let _ = issuer_sk2;

    Ok(())
}