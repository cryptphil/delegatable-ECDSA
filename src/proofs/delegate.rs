use std::time::Instant;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use crate::proofs::ecdsa::{gen_init_delegation_proof};
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use crate::cred::generate::IssuedEcdsaCredential;



/// Recursively wraps `inner_proof` inside `depth` layers of recursion.
/// Base case: `depth == 0` returns the inputs (cloned).
#[allow(dead_code)]
pub fn delegate_recursive<F, C, const D: usize>(
    verifier_data: &VerifierCircuitData<F, C, D>,
    inner_proof:   &ProofWithPublicInputs<F, C, D>,
    depth: usize,
) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Base case: no more recursion; return the provided layer.
    if depth == 0 {
        return Ok((verifier_data.clone(), inner_proof.clone()));
    }

    // Build one recursion layer
    let mut builder = CircuitBuilder::<F, D>::new(
        CircuitConfig::standard_recursion_zk_config()
    );

    let proof_t = builder.add_virtual_proof_with_pis(&verifier_data.common);
    builder.register_public_inputs(&proof_t.public_inputs);

    let constants_sigmas_cap_t =
        builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);
    let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    let verifier_circuit_t = VerifierCircuitTarget {
        constants_sigmas_cap: constants_sigmas_cap_t,
        circuit_digest:       circuit_digest_t,
    };

    builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_t, inner_proof)?;

    let data = builder.build::<C>();

    let rec_start = Instant::now();
    let proof_recursive = data.prove(pw)?;
    println!("Recursive proof generation time (layer {}): {:?}", depth, rec_start.elapsed());

    // Optional local verification of the newly created layer
    data.verify(proof_recursive.clone())?;
    println!("Recursive proof (layer {}) passed!", depth);

    // Recurse to add remaining layers
    let next_vd = data.verifier_data();
    delegate_recursive::<F, C, D>(&next_vd, &proof_recursive, depth - 1)
}

#[allow(dead_code)]
pub fn delegate(cred: &IssuedEcdsaCredential, iss_pk: &ECDSAPublicKey<Secp256K1>) -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let (verifier_data, proof) = gen_init_delegation_proof::<F, C, D>(cred, iss_pk)?;

    // Recursive proof
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let proof_t = builder.add_virtual_proof_with_pis(&verifier_data.common);
    builder.register_public_inputs(&proof_t.public_inputs); // Now has the same public inputs as the inner proof

    // This is how Philipp Sommer did it:
    // let vd = builder.add_virtual_verifier_data(verifier_data.common.config.fri_config.cap_height);
    // builder.verify_proof::<C>(&proof_t, &vd, &verifier_data.common);

    let constants_sigmas_cap_t =
        builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);
    let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    let verifier_circuit_t = VerifierCircuitTarget {
        constants_sigmas_cap: constants_sigmas_cap_t,
        circuit_digest: circuit_digest_t,
    };

    builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_t, &proof)?;

    let data = builder.build::<C>();

    let rec_proof_start = Instant::now();
    let proof_recursive = data.prove(pw)?;
    println!("Recursive proof generation time: {:?}", rec_proof_start.elapsed());

    data.verify(proof_recursive.clone())?;
    println!("Recursive proof passed!");
    println!("public inputs :{:?}", proof_recursive.public_inputs);
    Ok(())
}