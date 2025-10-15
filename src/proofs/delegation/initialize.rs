use crate::cred::credential::{
    generate_fixed_issuer_keypair, issue_fixed_dummy_credential, SignedECDSACredential,
};
use crate::proofs::ecdsa::{fill_ecdsa_witness, make_ecdsa_circuit, ECDSACircuitTargets};
use crate::proofs::hash::{fill_sha256_circuit_witness, make_sha256_circuit};
use crate::proofs::scalar_conversion::{
    fill_digest2scalar_witness, make_digest2scalar_circuit, Digest2ScalarTargets,
};
use crate::utils::recursion::get_dummy_proof;
use crate::utils::parsing::find_field_bit_indices;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::{dummy_circuit};
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_sha256::circuit::{array_to_bits, Sha256Targets};

pub struct InitDelegationTargets {
    pub ecdsa_targets: ECDSACircuitTargets<Secp256K1, Secp256K1Scalar>, // We fix this to Secp256K1 for now.
    pub b2c_targets: Digest2ScalarTargets,
    pub hash_targets: Sha256Targets,
    pub level_pi: Target,
    pub rev_num_bytes: usize,
}

pub struct InitDelegationProof<
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: ProofWithPublicInputs<F, Cfg, D>,
    pub verifier_data: VerifierCircuitData<F, Cfg, D>,
}

/// Create targets only (no build, no credential-bound data)
fn make_init_delegation_circuit<F, Cfg, const D: usize>(
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

    // ECDSA knowledge proof targets. Note that this also registers issuer pk as public input!
    let ecdsa_targets = make_ecdsa_circuit::<F, Cfg, D>(builder);

    // Byte-array to scalar consistency targets for the credential hash
    let b2c_targets = make_digest2scalar_circuit(builder);

    // SHA-256 preimage knowledge with selective reveal for the credential's public key bytes
    let hash_targets = make_sha256_circuit::<F, D>(builder, msg_len_bits, rev_idx, rev_num_bytes);

    // Public input for the level L=0 with an enforced zero value
    // Must be last target for recursion to work.
    let level_pi = builder.add_virtual_public_input(); // One Target = One Field Element, i.e. 64bit in Goldilocks

    builder.assert_zero(level_pi);

    Ok(InitDelegationTargets {
        ecdsa_targets,
        b2c_targets,
        hash_targets,
        level_pi,
        rev_num_bytes,
    })
}

pub fn build_init_delegation_circuit<F, Cfg, const D: usize>()
-> Result<(CircuitData<F, Cfg, D>, InitDelegationTargets)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

    // Create virtual targets
    let targets = make_init_delegation_circuit::<F, Cfg, D>(&mut builder)?;

    // Build circuit once
    let data = builder.build::<Cfg>();
    Ok((data, targets))
}

/// Prove using the built circuit and concrete inputs
pub fn prove_init_delegation<F, Cfg, const D: usize>(
    circuit: &CircuitData<F, Cfg, D>,
    targets: &InitDelegationTargets,
    cred: &SignedECDSACredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<InitDelegationProof<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
    Cfg::Hasher: AlgebraicHasher<F>,
{
    // Prepare concrete inputs (off-circuit)
    let cred_bytes_bits = array_to_bits(&cred.credential.to_bytes()?);
    let cred_digest = cred.credential.hash_digest()?;
    let cred_digest_bits = array_to_bits(&cred_digest);

    // Fill witnesses for saved targets
    let mut pw = PartialWitness::new();
    fill_ecdsa_witness::<F, Cfg, D>(&targets.ecdsa_targets, &mut pw, cred, iss_pk)?;
    fill_digest2scalar_witness(&targets.b2c_targets, &mut pw, &cred_digest, &cred.cred_hash)?;
    fill_sha256_circuit_witness::<F, Cfg, D>(
        &targets.hash_targets,
        &mut pw,
        &cred_bytes_bits,
        &cred_digest_bits,
    )?;
    pw.set_target(targets.level_pi, F::ZERO)?; // fill level witness with zero

    // Prove
    let proof = circuit.prove(pw)?;

    Ok(InitDelegationProof {
        proof: proof.clone(),
        verifier_data: circuit.verifier_data(),
    })
}

#[test]
fn test_init_delegation() -> Result<()> {
    // Generics
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // 1) Build once
    let build_start = std::time::Instant::now();
    let (data, targets) = build_init_delegation_circuit::<F, Cfg, D>()?;
    let build_time = build_start.elapsed();
    println!("init_delegation: Circuit build time: {:?}", build_time);

    // 2) Generate proof
    let issuer_kp = generate_fixed_issuer_keypair();
    let signed = issue_fixed_dummy_credential(&issuer_kp.sk)?;

    let prove_start = std::time::Instant::now();
    let init_proof = prove_init_delegation::<F, Cfg, D>(&data, &targets, &signed, &issuer_kp.pk)?;
    let prove_time = prove_start.elapsed();
    println!("init_delegation: Proof generation time: {:?}", prove_time);

    // 3) Verify proof
    let verify_start = std::time::Instant::now();
    init_proof.verifier_data.verify(init_proof.proof.clone())?;

    let verify_time = verify_start.elapsed();
    println!(
        "init_delegation: Proof verification time: {:?}",
        verify_time
    );

    // Sanity check
    assert!(!init_proof.proof.public_inputs.is_empty());

    Ok(())
}