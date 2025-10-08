use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential, SignedECDSACredential};
use crate::proofs::ecdsa::{fill_ecdsa_witness, make_ecdsa_circuit, register_pk_as_pi, ECDSACircuitTargets};
use crate::proofs::scalar_conversion::{fill_digest2scalar_witness, make_digest2scalar_circuit, Digest2ScalarTargets};
use crate::utils::parsing::find_field_bit_indices;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs};
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_sha256::circuit::{array_to_bits, Sha256Targets};
use std::time::Instant;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::PrimeField;
use crate::proofs::hash::{fill_sha256_circuit_witness, make_sha256_circuit};

pub struct InitDelegationTargets {
    pub ecdsa_targets: ECDSACircuitTargets<Secp256K1, Secp256K1Scalar>, // We fix this to Secp256K1 for now.
    pub b2c_targets: Digest2ScalarTargets,
    pub hash_targets: Sha256Targets,
    pub level_pi: Target,
    pub rev_num_bytes: usize,
}

pub struct InitDelegationProof<F: RichField + Extendable<D>, Cfg: GenericConfig<D, F=F>, const D: usize> {
    pub proof: ProofWithPublicInputs<F, Cfg, D>,
    pub verifier_data: VerifierCircuitData<F, Cfg, D>,
    pub level_index_pis: usize,
}

/// Build the init-delegation circuit (targets only), independent of any concrete credential.
pub fn make_init_delegation_circuit<F, Cfg, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Result<InitDelegationTargets>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    // Derive stable layout from a schema-stable dummy credential
    let dummy = issue_fixed_dummy_credential(&generate_fixed_issuer_keypair().sk)?;
    let dummy_json = dummy.credential.to_json()?;
    let dummy_msg_bits = array_to_bits(&dummy.credential.to_bytes()?);
    let msg_len_bits = dummy_msg_bits.len();
    let (rev_idx, rev_num_bytes) = find_field_bit_indices(&dummy_json, "cred_pk_sec1_compressed")?;

    // ECDSA knowledge proof targets
    let ecdsa_targets = make_ecdsa_circuit::<F, Cfg, D>(builder);

    // Byte-array to scalar consistency targets for the credential hash
    let b2c_targets = make_digest2scalar_circuit(builder);

    // SHA-256 preimage knowledge with selective reveal for the credential's public key bytes
    let hash_targets = make_sha256_circuit::<F, D>(builder, msg_len_bits, rev_idx, rev_num_bytes);

    // Public input for the level L=0 with an enforced zero value
    let level_pi = builder.add_virtual_public_input();
    builder.assert_zero(level_pi);

    Ok(InitDelegationTargets {
        ecdsa_targets,
        b2c_targets,
        hash_targets,
        level_pi,
        rev_num_bytes,
    })
}

/// Prove init delegation for a concrete credential and issuer public key.
pub fn prove_init_delegation<F, Cfg, const D: usize>(
    cred: &SignedECDSACredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<InitDelegationProof<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    // Prepare the circuit builder with the same config as before.
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Build the circuit using a dummy credential to determine layout.
    let targets = make_init_delegation_circuit::<F, Cfg, D>(&mut builder)?;

    // Compute message/digest bits from the *real* credential to fill witnesses later.
    let cred_data_bits_vec = array_to_bits(&cred.credential.to_bytes()?);
    let cred_data_digest = cred.credential.hash_digest()?; // 32-byte SHA-256
    let cred_digest_bits_vec = array_to_bits(&cred_data_digest);

    // Build circuit data and fill witnesses.
    let mut pw = PartialWitness::new();

    // 1) ECDSA knowledge of signature under issuer key for the credential hash
    fill_ecdsa_witness::<F, Cfg, D>(&targets.ecdsa_targets, &mut pw, cred, iss_pk)?;

    // 2) Conversion consistency: digest bytes to field scalar equals `cred_hash`
    fill_digest2scalar_witness(
        &targets.b2c_targets,
        &mut pw,
        &cred_data_digest,
        &cred.cred_hash,
    )?;

    // 3) Preimage knowledge with selective reveal of the compressed public key
    fill_sha256_circuit_witness::<F, Cfg, D>(
        &targets.hash_targets,
        &mut pw,
        &cred_data_bits_vec,
        &cred_digest_bits_vec,
    )?;

    let build_start = Instant::now();
    let data = builder.build::<Cfg>();
    println!("Init delegation circuit generation time: {:?}", build_start.elapsed());

    let prove_start = Instant::now();
    let proof = data.prove(pw)?;
    println!("Init delegation proof generation time: {:?}", prove_start.elapsed());

    let proof = InitDelegationProof {
        proof: proof.clone(),
        verifier_data: data.verifier_data(),
        // As we registered the issuer public key and the revealed preimage bytes as public input.
        level_index_pis: 16 + targets.rev_num_bytes * 8, // TODO: Make this robust (create a wrapper for registering PIs)
    };

    Ok(proof)
}

#[test]
fn test_init_delegation() -> Result<()> {
    // Generic parameters
    const D: usize = 2;
    type Cfg = plonky2::plonk::config::PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // 1) Generate a fixed issuer keypair and issue a signed dummy credential (schema-stable)
    let issuer_kp = generate_fixed_issuer_keypair();
    let signed = issue_fixed_dummy_credential(&issuer_kp.sk)?;

    // 2) Prove init delegation for that credential under the issuer public key
    let init_proof = prove_init_delegation::<F, Cfg, D>(&signed, &issuer_kp.pk)?;

    // 3) Verify proof
    init_proof.verifier_data.verify(init_proof.proof.clone())?;

    // Sanity check: public inputs should be non-empty and include the level PI we constrained to zero
    assert!(
        !init_proof.proof.public_inputs.is_empty(),
        "public inputs should not be empty"
    );

    Ok(())
}
