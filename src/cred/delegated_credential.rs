use std::ptr::null;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Sample;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::curve_types::{Curve, CurveScalar};
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use crate::cred::credential::{compressed_pubkey_hex, hash_credential_to_scalar, CredentialData, SignedECDSACredential};
use crate::proofs::delegate::gen_delegation_proof;
use crate::proofs::ecdsa::gen_ecdsa_proof;

// We fix the generics here for simplicity.
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
pub struct DelegatedCredential {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub verifier_data: VerifierCircuitData<F, C, D>,
    pub delegation_level: u8, // Part of proof (public input)
    pub cred_sk: ECDSASecretKey<Secp256K1>, // Part of proof (private input)
    pub cred_pk: ECDSAPublicKey<Secp256K1>, // Part of proof (public input)
    pub attr_commitment: Secp256K1Scalar, // Part of proof (public input)
    pub attributes: CredentialData // For now no subset functionality (private input)
}

// Derive a delegated credential from a base credential
pub fn initial_delegation(base_credential: &SignedECDSACredential, issuer_pk: &ECDSAPublicKey<Secp256K1>) -> anyhow::Result<DelegatedCredential> {
    // 1. Prove that base_credential is valid.
    let (init_verifier_data, init_proof) = gen_ecdsa_proof(base_credential, issuer_pk)?;

    // 2. Generate delegated version of the base credential
    let next_cred_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let next_cred_pk =
        ECDSAPublicKey((CurveScalar(next_cred_sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let credential_data = CredentialData {
        cred_pk_sec1_compressed: compressed_pubkey_hex(&next_cred_pk),
        name: base_credential.data.name.clone(),
        address: base_credential.data.address.clone(),
        birthdate: base_credential.data.birthdate.clone(),
    };

    let attribute_commitment = hash_credential_to_scalar(&credential_data)?;

    let delegated_credential = DelegatedCredential {
        proof: init_proof,
        verifier_data: init_verifier_data,
        delegation_level: 1,
        cred_sk: next_cred_sk,
        cred_pk: next_cred_pk,
        attr_commitment: attribute_commitment,
        attributes: credential_data,
    }

    // 3.
    gen_delegation_proof(init_verifier_data, init_proof, delegated_credential)
        


    Ok()
}

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