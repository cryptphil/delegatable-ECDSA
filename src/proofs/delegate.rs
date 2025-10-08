use std::hash::Hash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputsTarget, ProofWithPublicInputs};
use anyhow::Result;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::GateRef;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::ECDSAPublicKeyTarget;
use serde::Deserializer;
use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential, CredentialData};
use crate::proofs::ecdsa::{fill_ecdsa_witness, make_ecdsa_circuit, register_pk_as_pi};
use crate::proofs::hash::make_sha256_circuit;
use crate::proofs::scalar_conversion::fill_digest2scalar_witness;
use crate::utils::parsing::find_field_bit_indices;

/// Targets we need to fill witnesses for proving.
struct RecursionTargets<const D: usize> {
    verify_proofs: BoolTarget,
    inner: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
}

fn build_delegation_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>() -> (CircuitData<F, C, D>, CommonCircuitData<F, D>, RecursionTargets<D>)
where
    C::Hasher: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
{
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // PI layout: [pk_x_0_limb, pk_x_1_limb, pk_x_2_limb, pk_x_3_limb, pk_y_0_limb, pk_y_1_limb, pk_y_2_limb, pk_y_3_limb, cred_hash, level_target] // TODO: Double check this
    let issuer_pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
    register_pk_as_pi::<F, C, D>(&mut builder, &issuer_pk_target); // TODO: Check how this effects PIs of the circuit. Should be 8 limbs?

    let cred_hash = builder.add_virtual_hash_public_input(); // TODO: I think we dont need to register this as a PI as the make_sha256_circuit registers if we reveal that part of the cred.
    let level_target = builder.add_virtual_public_input();

    let verifier_data_target =builder.add_verifier_data_public_inputs();

    // Stabilized common data template for recursion; adjust PI count to match this circuit.
    let mut common_data = common_data_for_recursion::<F, C, D>();
    common_data.num_public_inputs = builder.num_public_inputs(); // TODO: This needs to happen after all the PIs are registered.

    // Base vs recursive step selector.
    let verify_proofs = builder.add_virtual_bool_target_safe();

    // Virtual proofs (inner) with public inputs of `common_data` shape.
    let inner = builder.add_virtual_proof_with_pis(&common_data);

    // Unpack PIs
    let inner_pis = &inner.public_inputs;

    // Check level, i.e., level_target = prev_level_target + 1
    let prev_level_target = inner_pis[9]; // 10th position // TODO: Check this
    let one = builder.constant(F::ONE);
    let exp_level = builder.add(prev_level_target, one);
    builder.connect(exp_level, level_target);

    // Hash cred in circuit (full credential must be a priv input)
    // Use a dummy credential to get input sizes.
    let dummy_cred_json = issue_fixed_dummy_credential(&generate_fixed_issuer_keypair().sk)?.credential.to_json()?; // We just do this to get a proper dummy credential
    let dummy_cred_bytes = dummy_cred_json.to_string().as_bytes()?;
    let dummy_cred_bits = plonky2_sha256::circuit::array_to_bits(dummy_cred_bytes);

    let (rev_idx, rev_num_bytes) = find_field_bit_indices(&dummy_cred_json, "cred_pk_sec1_compressed")?;
    // make_sha256_circuit defines the credential hash to be the public input as we reveal it
    let sha256_targets = make_sha256_circuit::<F, D>(&mut builder, dummy_cred_bits.len(), rev_idx, rev_num_bytes);
    builder.connect(sha256_targets.digest)

    // Add ECDSA Circuit (verify signature on hash of credential)
    let ecdsa_targets = make_ecdsa_circuit::<F, C, D>(&mut builder);
    builder.connect_affine_point(&ecdsa_targets.issuer_pk, &issuer_pk_target.0); // connect issuer public key to ecdsa circuit
    builder.extension(ecdsa_targets.msg.value, cred_hash.elements[0].) // connect credential hash PI to ecdsa circuit

    builder.connect_array(sha256_targets.message, &ecdsa_targets.msg)
    ecdsa_targets.msg // TODO: Connect message (i.e. cred hash - public input?)
    ecdsa_targets.sig // TODO: Connect signature (priv input)

    builder.connect_biguint(ecdsa_targets.msg.value, );


    fill_ecdsa_witness()



}

/// Prove multiple delegation steps.
fn prove_delegations<F, C, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    targets: &RecursionTargets<D>,
    base_pis: &[F],
    num_delegations: usize,
) -> Result<Vec<ProofWithPublicInputs<F, C, D>>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut proofs = Vec::with_capacity(num_delegations + 1);
    let base = prove_init_delegation::<F, C, D>(circuit, common_data, targets, base_pis)?;
    proofs.push(base);

    for _ in 0..num_delegations {
        let next = prove_delegation_step::<F, C, D>(circuit, targets, proofs.last().unwrap())?;
        proofs.push(next);
    }
    Ok(proofs)
}

/// Pass-structured fixed-point common data constructor used by Plonky2 recursion utilities.
fn common_data_for_recursion<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let num_consts = config.num_constants;
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(num_consts)));
    builder.build::<C>().common
}