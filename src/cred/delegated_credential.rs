use std::ptr::null;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Sample;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::curve_types::{Curve, CurveScalar};
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use serde::{Deserialize, Serialize};
use crate::cred::credential::{compressed_pubkey_hex, CredentialData, SignedECDSACredential};
use crate::proofs::delegate::gen_delegation_proof;
use crate::proofs::ecdsa::gen_ecdsa_proof;
use crate::utils::parsing::hash_to_scalar;

// We fix the generics here for simplicity.
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
pub struct DelegatedCredential {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub cred_sk: ECDSASecretKey<Secp256K1>, // Part of proof (private input)
    pub cred_pk: ECDSAPublicKey<Secp256K1>, // Part of proof (public input)
    pub attributes: CredentialData, // For now no subset functionality
    pub delegation_level: u8, // Part of proof (public input)
    pub attr_commitment: Secp256K1Scalar, // Part of proof (public input)
}

// Derive a delegated credential from a base credential
pub fn initial_delegation(base_credential: &SignedECDSACredential, issuer_pk: &ECDSAPublicKey<Secp256K1>) -> anyhow::Result<DelegatedCredential> {
    // 1. Prove that base_credential is valid. Note that init_proof holds the public inputs of the proof i.e. the issuer public key
    let (init_verifier_data, init_proof) = gen_ecdsa_proof(base_credential, issuer_pk)?;

    // 2. Prepare delegated version of the base credential
    let next_cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let next_cred_pk =
        ECDSAPublicKey((CurveScalar(next_cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let delegated_credential_data = CredentialData {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&next_cred_pk),
        name: base_credential.data.name.clone(),
        address: base_credential.data.address.clone(),
        birthdate: base_credential.data.birthdate.clone(),
    };

    let cred_json = delegated_credential_data.to_json_bytes()?;
    let cred_hash = hash_to_scalar(&cred_json)?;

    // 3. Generate proof of delegation for new credential data
    let (verifier_data, proof) = gen_delegation_proof(&init_verifier_data, &init_proof, &delegated_credential_data, 1, &cred_hash, &next_cred_sk, &next_cred_pk, issuer_pk)?;

    // 4. Construct delegated credential type
    let delegated_credential = DelegatedCredential {
        proof,
        verifier_data,
        cred_sk: next_cred_sk,
        cred_pk: next_cred_pk,
        attributes: delegated_credential_data,
        delegation_level: 1, // First level
        attr_commitment: cred_hash
    };

    Ok(delegated_credential)
}

/*
pub fn subsequent_delegation(prev_credential: &DelegatedCredential) -> anyhow::Result<DelegatedCredential> {
    let next_cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let next_cred_pk =
        ECDSAPublicKey((CurveScalar(next_cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let credential_data = CredentialData {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&next_cred_pk),
        name: prev_credential.attributes.name.clone(),
        address: prev_credential.attributes.address.clone(),
        birthdate: prev_credential.attributes.birthdate.clone(),
    };

    let attribute_commitment = hash_credential_to_scalar(&credential_data)?;

    Ok(DelegatedCredential {
        proof: ,
        delegation_level: 10,
        cred_sk: next_cred_sk,
        cred_pk: next_cred_pk,
        attr_commitment: attribute_commitment,
        attributes: credential_data,
    })
}

 */