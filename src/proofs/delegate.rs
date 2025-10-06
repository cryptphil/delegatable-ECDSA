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
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::ECDSAPublicKeyTarget;
use crate::proofs::ecdsa::register_pk_as_pi;

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

    // PI layout: [pk_x_0, pk_x_1, pk_x_2, pk_x_3, pk_y_0, pk_y_1, pk_y_2, pk_y_3, level_target] // TODO: Double check this
    let issuer_pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
    register_pk_as_pi::<F, C, D>(&mut builder, &issuer_pk_target); // TODO: Check how this effects PIs of the circuit. Should be 8 limbs?

    let level_target = builder.add_virtual_public_input();

    let verifier_data_target =builder.add_verifier_data_public_inputs();

    // Stabilized common data template for recursion; adjust PI count to match this circuit.
    let mut common_data = common_data_for_recursion::<F, C, D>();
    common_data.num_public_inputs = builder.num_public_inputs();

    // Base vs recursive step selector.
    let verify_proofs = builder.add_virtual_bool_target_safe();

    // Virtual proofs (inner) with public inputs of `common_data` shape.
    let inner = builder.add_virtual_proof_with_pis(&common_data);

    // Unpack PIs
    let inner_pis = &inner.public_inputs;

    // Check level, i.e., level_target = prev_level_target + 1
    let prev_level_target = inner_pis[8]; // 9th position
    let one = builder.constant(F::ONE);
    let exp_level = builder.add(prev_level_target, one);
    builder.connect(exp_level, level_target);

    // Add ECDSA Circuit

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