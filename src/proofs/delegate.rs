use std::hash::Hash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputsTarget, ProofWithPublicInputs};
use anyhow::Result;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::GateRef;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use hashbrown::HashMap;

use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::ECDSAPublicKeyTarget;
use serde::Deserializer;
use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential, CredentialData};
use crate::proofs::ecdsa::{fill_ecdsa_witness, make_ecdsa_circuit, register_pk_as_pi};
use crate::proofs::hash::make_sha256_circuit;
use crate::proofs::init_delegation::{build_init_delegation_circuit_data, prove_init_delegation};
use crate::proofs::scalar_conversion::fill_digest2scalar_witness;
use crate::utils::parsing::find_field_bit_indices;

/// Targets we need to fill witnesses for proving.
pub struct DelegationTargets<const D: usize> {
    pub initial_selector: BoolTarget,
    pub initial_proof: ProofWithPublicInputsTarget<D>,
    pub delegation_proof: ProofWithPublicInputsTarget<D>,
    pub outer_pi_slots: Vec<plonky2::iop::target::Target>,
    verifier_data_target: VerifierCircuitTarget,
}

pub fn build_delegation_circuit<F, C, const D: usize>(
    // how many public inputs do you want to forward (must equal the PI count of both inner circuits)
    forwarded_pi_len: usize,
) -> (CircuitData<F, C, D>, DelegationTargets<D>)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // 1) Reserve OUTER public inputs (forwarding slots) before freezing common.
    let mut outer_pi_slots = Vec::with_capacity(forwarded_pi_len);
    for _ in 0..forwarded_pi_len {
        outer_pi_slots.push(builder.add_virtual_public_input());
    }

    let verifier_data_target = builder.add_verifier_data_public_inputs();

    // 2) Freeze stabilized recursion shape for both inner proofs.
    let mut common_data = common_data_for_recursion::<F, C, D>();
    common_data.num_public_inputs = builder.num_public_inputs();

    // 3) Allocate two virtual inner proofs with *identical* PI shape.
    let initial_proof    = builder.add_virtual_proof_with_pis(&common_data);
    let delegation_proof = builder.add_virtual_proof_with_pis(&common_data);

    // 4) Wire OUTER PI slots to BOTH inner proofs' public inputs 1:1.
    //assert_eq!(initial_proof.public_inputs.len(), forwarded_pi_len);
    //assert_eq!(delegation_proof.public_inputs.len(), forwarded_pi_len);
    let last = forwarded_pi_len - 1; // last slot is the delegation level
    for i in 0..last {
        builder.connect(outer_pi_slots[i], initial_proof.public_inputs[i]);
        builder.connect(outer_pi_slots[i], delegation_proof.public_inputs[i]);
    }

    // 5) Initial proof selector: true => verifies INIT PROOF, false => verifies DELEGATION PROOF
    let initial_selector = builder.add_virtual_bool_target_safe();
    let initial_selector_not    = builder.not(initial_selector);

    // 6) Constrain delegation level (last PI slot is the level)
    let last = forwarded_pi_len - 1;
    let outer_level         = outer_pi_slots[last];
    let inner_init_level    = initial_proof.public_inputs[last];
    let inner_deleg_level   = delegation_proof.public_inputs[last];

    // inner_deleg_level + 1
    let one                 = builder.one();
    let inner_plus_one      = builder.add(inner_deleg_level, one);

    // expected_outer_level = if init { inner_init_level } else { inner_deleg_level + 1 }
    let expected_outer_level = builder.select(initial_selector, inner_init_level, inner_plus_one);

    // Enforce outer level equals the branch-specific expectation
    builder.connect(outer_level, expected_outer_level);

    // 7) Conditionally verify either proof (or dummy) with its own verifier data.
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(initial_selector, &initial_proof, &common_data)
        .expect("init conditional verify failed");
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(initial_selector_not, &delegation_proof, &common_data)
        .expect("delegation conditional verify failed");

    // 8) Build outer circuit
    let cd = builder.build::<C>();

    let targets = DelegationTargets {
        initial_selector,
        initial_proof,
        delegation_proof,
        outer_pi_slots,
        verifier_data_target
    };
    (cd, targets)
}

fn prove_delegation_base<F, C, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    initial_proof: &ProofWithPublicInputs<F, C, D>,
    targets: &DelegationTargets<D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    // Sanity: inner PI shape must match stabilized shape.
    assert_eq!(
        initial_proof.public_inputs.len(),
        common_data.num_public_inputs,
        "init proof PI len ({}) must equal stabilized PI count ({})",
        initial_proof.public_inputs.len(),
        common_data.num_public_inputs
    );

    // Build a dummy "delegation" proof whose PIs match the OUTER PIs.
    // In base mode, the OUTER PIs equal the INIT inner PIs
    let pi_map: HashMap<usize, F> = initial_proof
        .public_inputs
        .iter()
        .copied()
        .enumerate()
        .collect();

    let delegation_dummy_proof =
        cyclic_base_proof(common_data, &circuit.verifier_only, pi_map);

    let mut pw = PartialWitness::new();
    pw.set_bool_target(targets.initial_selector, true)?;
    pw.set_proof_with_pis_target::<C, D>(&targets.initial_proof, initial_proof)?;
    pw.set_proof_with_pis_target::<C, D>(&targets.delegation_proof, &delegation_dummy_proof)?;
    pw.set_verifier_data_target(&targets.verifier_data_target, &circuit.verifier_only)?;

    let proof0 = circuit.prove(pw)?;
    Ok(proof0)
}

/*
/// Prove multiple delegation steps.
fn prove_delegations<F, C, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    common_data: &CommonCircuitData<F, D>,
    targets: &DelegationTargets<D>,
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
}*/

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

#[test]
fn test_prove_delegation_base() -> Result<()> {
    // Generics
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // --- Build init-delegation circuit and produce an init proof ---
    let (init_cd, init_targets) = build_init_delegation_circuit_data::<F, Cfg, D>()?;

    let issuer_kp = generate_fixed_issuer_keypair();
    let signed = issue_fixed_dummy_credential(&issuer_kp.sk)?;

    let init_proof = prove_init_delegation::<F, Cfg, D>(&init_cd, &init_targets, &signed, &issuer_kp.pk)?;

    // The delegation wrapper must forward exactly the same number of PIs as the inner proof exposes.
    let forwarded_pi_len = init_proof.proof.public_inputs.len();

    // --- Build delegation (outer) circuit that forwards all PIs and enforces the level rule ---
    let (deleg_cd, deleg_targets) = build_delegation_circuit::<F, Cfg, D>(forwarded_pi_len);

    // Stabilized common data with matching PI count for cyclic verification utilities.
    let mut common = common_data_for_recursion::<F, Cfg, D>();
    common.num_public_inputs = forwarded_pi_len;

    // --- Prove base step: verify INIT branch, delegation branch is dummy ---
    let prove_start = std::time::Instant::now();
    let outer_proof = prove_delegation_base::<F, Cfg, D>(
        &deleg_cd,
        &common,
        &init_proof.proof,
        &deleg_targets,
    )?;
    let prove_time = prove_start.elapsed();
    println!("delegation(base): outer proof generation time: {:?}", prove_time);

    // --- Verify outer proof ---
    deleg_cd.verifier_data().verify(outer_proof.clone())?;

    // Sanity: in base mode, the outer PIs should match the init proof's PIs (1:1 wiring).
    assert_eq!(outer_proof.public_inputs, init_proof.proof.public_inputs);

    Ok(())
}