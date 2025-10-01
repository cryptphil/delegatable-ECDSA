use crate::cred::credential::SignedECDSACredential;
use crate::proofs::ecdsa::{fill_ecdsa_witness, make_ecdsa_circuit, register_pk_as_pi};
use crate::proofs::hash::{fill_sha256_circuit_witness, make_sha256_circuit};
use crate::proofs::scalar_conversion::{fill_digest2scalar_witness, make_digest2scalar_circuit};
use crate::utils::parsing::find_field_bit_indices;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::ECDSAPublicKeyTarget;
use plonky2_sha256::circuit::array_to_bits;
use std::time::Instant;

pub struct InitDelegationProof<F: RichField + Extendable<D>, Cfg: GenericConfig<D, F=F>, const D: usize> {
    pub proof: ProofWithPublicInputs<F, Cfg, D>,
    pub verifier_data: VerifierCircuitData<F, Cfg, D>,
    pub level_index_pis: usize,
}

pub struct DelegationCircuit<F: RichField + Extendable<D>, Cfg: GenericConfig<D, F=F>, const D: usize> {
    pub data: CircuitData<F, Cfg, D>,
    pub inner_proof_target: ProofWithPublicInputsTarget<D>,
    pub issuer_pk_target: ECDSAPublicKeyTarget<Secp256K1>,
    pub new_level_target: Target,
    pub level_index_pis: usize, // which position in public_inputs holds the proof level L.
    // Add other targets as well
}

// TODO: potentially also split up in a build circuit function with all the targets and then a dedicated prove function.
pub fn init_delegation<F, Cfg, const D: usize>(
    cred: &SignedECDSACredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<InitDelegationProof<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Prove knowledge of a valid ECDSA signature.
    let ecdsa_circuit = make_ecdsa_circuit::<F, Cfg, D>(&mut builder);
    fill_ecdsa_witness::<F, Cfg, D>(&ecdsa_circuit, &mut pw, cred, iss_pk)?;

    // Prove that the credential hash as bytes converts to the credential hash as scalar.
    let cred_data_digest = cred.credential.hash_digest()?;
    let b2c_circuit = make_digest2scalar_circuit(&mut builder);
    fill_digest2scalar_witness(&b2c_circuit, &mut pw, &cred_data_digest, &cred.cred_hash)?;

    // Prove knowledge of the preimage of the credential hash while selectively revealing the
    // hashed public key.
    let cred_data_bits_vec = array_to_bits(&cred.credential.to_bytes()?);
    let cred_data_bits = cred_data_bits_vec.as_slice();
    let cred_digest_bits_vec = array_to_bits(&cred_data_digest);
    let cred_digest_bits = cred_digest_bits_vec.as_slice();
    let cred_json = cred.credential.to_json()?;

    // Prove knowledge of the sha256 preimage while revealing the credential public key.
    let (rev_idx, rev_num_bytes) = find_field_bit_indices(&cred_json, "cred_pk_sec1_compressed")?;
    let hash_circuit = make_sha256_circuit::<F, D>(&mut builder, cred_data_bits.len(), rev_idx, rev_num_bytes);
    fill_sha256_circuit_witness::<F, Cfg, D>(&hash_circuit, &mut pw, cred_data_bits, cred_digest_bits)?;
    // TODO: Convert the revealed public key bytes to some curve scalar or just in a format we want to work with later (hex is also fine I guess).

    // Register the level L=0 as public input.
    let level = builder.add_virtual_public_input();
    builder.assert_zero(level);

    let build_start = Instant::now();
    let data = builder.build::<Cfg>();
    println!("Init delegation circuit generation time: {:?}", build_start.elapsed());
    let prove_start = Instant::now();
    let proof = data.prove(pw)?;
    println!("Init delegation proof generation time: {:?}", prove_start.elapsed());

    let circuit = InitDelegationProof {
        proof: proof.clone(),
        verifier_data: data.verifier_data(),
        // As we registered the issuer public key and the revealed preimage bytes as public input.
        level_index_pis: 16 + rev_num_bytes * 8, // TODO: Make this robust (create a wrapper for registering PIS)
    };

    Ok(circuit)
}


/// Build a delegation circuit that verifies an inner proof recursively for the given verifier data
/// and enforces that the new level L is increased by 1 compared to the inner proof level, given in
/// the public inputs of the inner proof at position `level_index_in_inner_pis`.
pub fn build_delegation_circuit<F, Cfg, const D: usize>(
    verifier_data: &VerifierCircuitData<F, Cfg, D>, // verifier_data of the *inner* circuit being verified
    level_idx_inner_pis: usize,               // which position in inner proof public_inputs holds the level L
) -> DelegationCircuit<F, Cfg, D>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
    <Cfg as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

    let proof_target = builder.add_virtual_proof_with_pis(&verifier_data.common);
    let issuer_pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());

    register_pk_as_pi::<F, Cfg, D>(&mut builder, &issuer_pk_target);

    // Increase the level L by 1.
    let l_new = builder.add_virtual_public_input();
    let prev_level_target = proof_target.public_inputs[level_idx_inner_pis];
    let one = builder.constant(F::ONE);
    let exp_level = builder.add(prev_level_target, one);
    builder.connect(exp_level, l_new);

    let constants_sigmas_cap_t =
        builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);
    let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    let verifier_circuit_t = VerifierCircuitTarget {
        constants_sigmas_cap: constants_sigmas_cap_t,
        circuit_digest:       circuit_digest_t,
    };

    builder.verify_proof::<Cfg>(&proof_target, &verifier_circuit_t, &verifier_data.common);

    let data = builder.build::<Cfg>();

    DelegationCircuit {
        data,
        inner_proof_target: proof_target,
        issuer_pk_target,
        new_level_target: l_new,
        level_index_pis: 16,
    }
}

pub fn prove_delegation_step<F, Cfg, const D: usize>(
    rec_circuit: &DelegationCircuit<F, Cfg, D>,
    inner_proof: &ProofWithPublicInputs<F, Cfg, D>,
    issuer_pk: &ECDSAPublicKey<Secp256K1>,
    level_idx_inner_pis: usize,
) -> Result<ProofWithPublicInputs<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
    <Cfg as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&rec_circuit.inner_proof_target, inner_proof)?;
    pw.set_biguint_target(&rec_circuit.issuer_pk_target.0.x.value, &issuer_pk.0.x.to_canonical_biguint())?;
    pw.set_biguint_target(&rec_circuit.issuer_pk_target.0.y.value, &issuer_pk.0.y.to_canonical_biguint())?;

    let inner_level = inner_proof.public_inputs[level_idx_inner_pis].to_canonical_u64();
    let new_level = inner_level + 1;

    pw.set_target(rec_circuit.new_level_target, F::from_canonical_u64(new_level))?;

    let prove_start = Instant::now();
    let proof = rec_circuit.data.prove(pw)?;
    println!("Delegation step level {} proof generation time: {:?}", new_level, prove_start.elapsed());

    Ok(proof)
}

