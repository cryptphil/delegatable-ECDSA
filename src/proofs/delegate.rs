use std::hash::Hash;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputsTarget, ProofWithPublicInputs};
use anyhow::Result;
use hashbrown::HashMap;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::init_delegation::{build_init_delegation_circuit, prove_init_delegation};
use crate::utils::recursion::{common_data_for_recursion, get_dummy_proof};

/// Targets we need to fill witnesses for proving.
pub struct DelegationTargets<const D: usize> {
    pub outer_pis: Vec<Target>,
    pub level_idx: usize, // position of the delegation level in pis

    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget, // VK for recursion circuit (as PIs)

    pub base_proof: ProofWithPublicInputsTarget<D>,
    pub base_verifier_data_target: VerifierCircuitTarget,  // VK for base circuit (private)
}

/// Build the delegation circuit.
/// - `base_common` is the `CommonCircuitData` of your INIT circuit (the base case).
/// - Returns the OUTER circuit and its targets.
pub fn build_delegation_circuit<F, C, const D: usize>(
    base_common: &CommonCircuitData<F, D>,
)  -> (CircuitData<F, C, D>, CommonCircuitData<F, D>, DelegationTargets<D>)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // We require the delegation circuit to expose the same public inputs as the base circuit.
    let n_pi = base_common.num_public_inputs;
    assert!(n_pi > 0, "expected at least one public input (level)");
    let level_idx = n_pi - 1;

    // Outer public inputs (these will be *forwarded* from base/inner).
    let mut outer_pis = Vec::with_capacity(n_pi);
    for _ in 0..n_pi {
        outer_pis.push(builder.add_virtual_public_input());
    }
    let level = outer_pis[level_idx];

    // Expose recursion VK as public inputs (needed for cyclic recursion)
    let verifier_data_target = builder.add_verifier_data_public_inputs();

    // Common data for the recursive (inner) proof — must match *this* outer shape.
    let mut cyclic_common = common_data_for_recursion::<F, C, D>();
    cyclic_common.num_public_inputs = builder.num_public_inputs();

    // Proof targets:
    //   - inner: previous delegation proof (same shape as this circuit)
    //   - base:  init (base) proof
    let inner = builder.add_virtual_proof_with_pis(&cyclic_common);
    let base = builder.add_virtual_proof_with_pis(base_common);

    let base_verifier_data_target =
        builder.add_virtual_verifier_data(base_common.config.fri_config.cap_height);

    // Select which branch to verify based on level == 0
    let zero = builder.zero();
    let one = builder.one();
    let is_base = builder.is_equal(level, zero);
    let not_base = builder.not(is_base);

    // Forward PIs: for all but the 'level' position, forward from base vs inner.
    for i in 0..level_idx {
        let selected = builder.select(is_base, base.public_inputs[i], inner.public_inputs[i]);
        builder.connect(outer_pis[i], selected);
    }

    // Level rule:
    //   If base: level == 0
    //   Else:   level == inner_level + 1
    let inner_level = inner.public_inputs[level_idx];
    let next_level_if_rec = builder.add(inner_level, one);
    let expected_level = builder.select(is_base, zero, next_level_if_rec);
    builder.connect(level, expected_level);

    // Conditional verification:
    // - Verify INNER (previous delegation) iff NOT base, otherwise allow dummy.
    builder.conditionally_verify_cyclic_proof_or_dummy::<C>(not_base, &inner, &cyclic_common).unwrap();
    // - Verify BASE proof iff is_base, otherwise allow dummy.
    builder
        .conditionally_verify_proof_or_dummy::<C>(is_base, &base, &base_verifier_data_target, base_common).unwrap();

    let cd = builder.build::<C>();

    let targets = DelegationTargets {
        outer_pis,
        base_proof: base,
        inner_proof: inner,
        level_idx,
        verifier_data_target,
        base_verifier_data_target
    };
    (cd, cyclic_common, targets)
}

/// Prove the *base* outer step (level == 0).
/// Verifies the INIT proof; the inner (delegation) branch is dummy.
pub fn prove_delegation_base<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
    base_circuit: &CircuitData<F, C, D>,
    base_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    // Outer PIs must match the base proof's PI shape.
    let n_outer = del_targets.outer_pis.len();
    assert_eq!(
        base_proof.public_inputs.len(),
        n_outer,
        "PI shape mismatch: base_proof has {}, outer expects {}",
        base_proof.public_inputs.len(),
        n_outer
    );

    let mut pw = PartialWitness::new();

    // Forward all outer public inputs 1:1 (includes level at last index, which is 0 in base).
    for i in 0..n_outer {
        pw.set_target(del_targets.outer_pis[i], base_proof.public_inputs[i])?;
    }

    let mut overrides: HashMap<usize, F> = HashMap::new();
    overrides.insert(del_targets.level_idx, base_proof.public_inputs[del_targets.level_idx]);
    let del_proof_dummy = cyclic_base_proof::<F, C, D>(
        &del_circuit.common,
        &del_circuit.verifier_only,
        overrides,
    );

    pw.set_proof_with_pis_target::<C, D>(&del_targets.base_proof, base_proof)?;
    pw.set_proof_with_pis_target::<C, D>(&del_targets.inner_proof, &del_proof_dummy)?;
    pw.set_verifier_data_target(&del_targets.verifier_data_target, &del_circuit.verifier_only)?;
    pw.set_verifier_data_target(&del_targets.base_verifier_data_target, &base_circuit.verifier_only)?;

    Ok(del_circuit.prove(pw)?)
}

/// Prove a *recursive* delegation step (level > 0).
/// Verifies the previous OUTER proof and enforces `level = prev_level + 1`.
/// The base (init) branch is dummy here.
pub fn prove_delegation_step<F, C, const D: usize>(
    del_circuit: &CircuitData<F, C, D>,
    del_targets: &DelegationTargets<D>,
    base_circuit: &CircuitData<F, C, D>,
    prev_del_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    // Only the OUTER PIs (not the VK PIs)
    let n_outer = del_targets.outer_pis.len();
    let lvl_idx = del_targets.level_idx;

    // Forward all outer PIs; increment delegation level
    let mut next_pis = prev_del_proof.public_inputs[..n_outer].to_vec();
    next_pis[lvl_idx] = next_pis[lvl_idx] + F::ONE;

    let mut pw = PartialWitness::new();
    for i in 0..n_outer {
        pw.set_target(del_targets.outer_pis[i], next_pis[i]);
    }

    // Proofs: inner = previous outer (real); base = dummy (unused in this branch)
    let base_dummy = get_dummy_proof::<F, C, D>(base_circuit);
    pw.set_proof_with_pis_target::<C, D>(&del_targets.inner_proof, prev_del_proof)?;
    pw.set_proof_with_pis_target::<C, D>(&del_targets.base_proof, &base_dummy)?;
    pw.set_verifier_data_target(&del_targets.verifier_data_target, &del_circuit.verifier_only)?;
    pw.set_verifier_data_target::<C, D>(&del_targets.base_verifier_data_target, &base_circuit.verifier_only)?;

    let proof = del_circuit.prove(pw)?;
    Ok(proof)
}

#[test]
fn test_delegation_flow() -> anyhow::Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // Build init-delegation circuit and produce a real init proof.
    let (init_cd, init_targets) = build_init_delegation_circuit::<F, Cfg, D>()?;
    let issuer = generate_fixed_issuer_keypair();
    let signed = issue_fixed_dummy_credential(&issuer.sk)?;
    let init_proof =
        prove_init_delegation::<F, Cfg, D>(&init_cd, &init_targets, &signed, &issuer.pk)?;

    // Build delegation wrapper using the INIT common data (PI shape source).
    let (outer_cd, _del_common, targets) =
        build_delegation_circuit::<F, Cfg, D>(&init_cd.common);

    // PI shape sanity: outer expects the same number of PIs as the base/init proof exposes.
    assert_eq!(
        targets.outer_pis.len(),
        init_proof.proof.public_inputs.len(),
        "outer PI count must match base proof PIs"
    );

    // Base outer proof (level = 0) — verifies init proof.
    let base_outer = prove_delegation_base::<F, Cfg, D>(
        &outer_cd,
        &targets,
        &init_cd,
        &init_proof.proof,
    )?;
    outer_cd.verifier_data().verify(base_outer.clone())?;
    assert_eq!(base_outer.public_inputs[targets.level_idx], F::ZERO);

    // Step 1 — verifies previous outer proof, increments level to 1.
    let step1 = prove_delegation_step::<F, Cfg, D>(
        &outer_cd,
        &targets,
        &init_cd,      // pass base circuit for the dummy in the disabled branch
        &base_outer,
    )?;
    outer_cd.verifier_data().verify(step1.clone())?;
    assert_eq!(step1.public_inputs[targets.level_idx], F::ONE);

    // Step 2 — level becomes 2.
    let step2 = prove_delegation_step::<F, Cfg, D>(
        &outer_cd,
        &targets,
        &init_cd,
        &step1,
    )?;
    outer_cd.verifier_data().verify(step2.clone())?;
    assert_eq!(step2.public_inputs[targets.level_idx], F::from_canonical_u64(2));

    // Forwarding sanity: all non-level PIs are forwarded unchanged each step.
    for i in 0..targets.level_idx {
        assert_eq!(base_outer.public_inputs[i], init_proof.proof.public_inputs[i]);
        assert_eq!(step1.public_inputs[i],      base_outer.public_inputs[i]);
        assert_eq!(step2.public_inputs[i],      step1.public_inputs[i]);
    }

    Ok(())
}