use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegation::delegate::{build_delegation_circuit, prove_delegation_base, prove_delegation_step};
use crate::proofs::delegation::initialize::{build_init_delegation_circuit, prove_init_delegation};

/// Public wrapper that exposes the *delegation* public inputs and proves
/// inside ZK that there exists a valid delegation proof with exactly those PIs.
pub struct PresentationTargets<const D: usize> {
    /// Public inputs we want to present (must match the first `n_outer_pis` of the delegation proof).
    pub presented_pis: Vec<Target>,
    /// Private: the full delegation proof object to be verified inside the wrapper.
    pub inner_delegation_proof: ProofWithPublicInputsTarget<D>,
    /// Public: verifier data (VK) of the delegation circuit, to bind the program.
    pub delegation_vk_pis: VerifierCircuitTarget,
}

/// Build a ZK wrapper circuit that:
/// - exposes `n_outer_pis` public inputs (the *outer* PIs of the delegation circuit),
/// - exposes the *delegation VK* as public inputs (binds to the exact delegation program),
/// - takes a *private* delegation proof,
/// - checks that the delegation proof is valid and that its first `n_outer_pis` PIs equal the presented ones.
///
/// `delegation_common` should be the `CommonCircuitData` of your delegation circuit.
pub fn build_presentation_circuit<F, C, const D: usize>(
    delegation_common: &CommonCircuitData<F, D>,
    n_outer_pis: usize,
) -> (CircuitData<F, C, D>, PresentationTargets<D>)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    // ZK-enabled recursion config.
    let cfg = CircuitConfig::standard_recursion_zk_config();
    let mut b = CircuitBuilder::<F, D>::new(cfg);

    // 1) Public: the presented outer PIs we want to reveal/commit to.
    let mut presented_pis = Vec::with_capacity(n_outer_pis);
    for _ in 0..n_outer_pis {
        presented_pis.push(b.add_virtual_public_input());
    }

    // 2) Public: the delegation circuit's VK as public inputs (bind to exact program).
    let delegation_vk_pis = b.add_verifier_data_public_inputs();

    // 3) Private: a full proof of the *delegation* circuit.
    let inner_delegation_proof = b.add_virtual_proof_with_pis(delegation_common);

    // 4) Forward the first `n_outer_pis` from the inner proof to the presented PIs.
    for i in 0..n_outer_pis {
        b.connect(presented_pis[i], inner_delegation_proof.public_inputs[i]);
    }

    // 5) Verify the inner delegation proof inside this wrapper.
    b.verify_proof::<C>(&inner_delegation_proof, &delegation_vk_pis, delegation_common);

    let cd = b.build::<C>();
    let targets = PresentationTargets {
        presented_pis,
        inner_delegation_proof,
        delegation_vk_pis,
    };
    (cd, targets)
}

/// Produce a presentation proof for a given delegation proof.
/// - Sets the wrapper's public inputs to the *outer* PIs of `delegation_proof`
///   (the first `targets.presented_pis.len()` entries).
/// - Binds the wrapper to the delegation circuit via its VK.
/// - Verifies the delegation proof inside.
pub fn prove_presentation<F, C, const D: usize>(
    presentation_circuit: &CircuitData<F, C, D>,
    presentation_targets: &PresentationTargets<D>,
    delegation_circuit: &CircuitData<F, C, D>,
    delegation_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    let n_outer = presentation_targets.presented_pis.len();
    assert!(
        delegation_proof.public_inputs.len() >= n_outer,
        "delegation proof has fewer PIs than expected outer count"
    );

    let mut pw = PartialWitness::<F>::new();

    // 1) Set wrapper's presented (public) PIs to the first `n_outer` PIs of the delegation proof.
    for i in 0..n_outer {
        pw.set_target(presentation_targets.presented_pis[i], delegation_proof.public_inputs[i])?;
    }

    // 2) Provide the inner delegation proof (private witness).
    pw.set_proof_with_pis_target::<C, D>(&presentation_targets.inner_delegation_proof, delegation_proof)?;

    // 3) Bind VK of the delegation circuit as public inputs of the wrapper.
    pw.set_verifier_data_target(&presentation_targets.delegation_vk_pis, &delegation_circuit.verifier_only)?;

    // 4) Prove the wrapper.
    presentation_circuit.prove(pw).map_err(Into::into)
}

#[test]
fn test_presentation() -> Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // Build init-delegation circuit and produce a real init proof.
    let (initial_delegation_circuit, initial_delegation_targets) = build_init_delegation_circuit::<F, Cfg, D>()?;
    let issuer_keypair = generate_fixed_issuer_keypair();
    let signed_cred = issue_fixed_dummy_credential(&issuer_keypair.sk)?;
    let init_del_proof =
        prove_init_delegation::<F, Cfg, D>(&initial_delegation_circuit, &initial_delegation_targets, &signed_cred, &issuer_keypair.pk)?;

    // Build delegation using the INIT common data (PI shape source).
    let (delegation_circuit, _del_common, delegation_targets) =
        build_delegation_circuit::<F, Cfg, D>(&initial_delegation_circuit.common);

    // Base outer proof (level = 0) — verifies init proof.
    let base_outer = prove_delegation_base::<F, Cfg, D>(
        &delegation_circuit,
        &delegation_targets,
        &initial_delegation_circuit,
        &init_del_proof.proof,
    )?;
    delegation_circuit.verifier_data().verify(base_outer.clone())?;

    // Step 1 — verifies previous outer proof, increments level to 1.
    let step1 = prove_delegation_step::<F, Cfg, D>(
        &delegation_circuit,
        &delegation_targets,
        &initial_delegation_circuit,      // pass base circuit for the dummy in the disabled branch
        &base_outer,
    )?;
    delegation_circuit.verifier_data().verify(step1.clone())?;

    // Step 2 — level becomes 2.
    let step2 = prove_delegation_step::<F, Cfg, D>(
        &delegation_circuit,
        &delegation_targets,
        &initial_delegation_circuit,
        &step1,
    )?;
    delegation_circuit.verifier_data().verify(step2.clone())?;

    let n_outer = delegation_targets.outer_pis.len();

    // Build the ZK wrapper ONCE.
    let (wrapper_cd, wt) =
        build_presentation_circuit::<F, Cfg, D>(&delegation_circuit.common, n_outer);

    // Wrap a delegation proof (e.g., latest step).
    let pres = prove_presentation::<F, Cfg, D>(&wrapper_cd, &wt, &delegation_circuit, &step2)?;
    // Verify the presentation proof (ZK).
    wrapper_cd.verify(pres.clone())?;

    assert_eq!(pres.public_inputs, step2.public_inputs);
    Ok(())
}