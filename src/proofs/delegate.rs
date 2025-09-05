use crate::cred::generate::IssuedEcdsaCredential;
use crate::proofs::ecdsa::make_ecdsa_proof;
use anyhow::Result;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use std::time::Instant;

#[allow(dead_code)]
pub fn init_delegate(cred: &IssuedEcdsaCredential, iss_pk: &ECDSAPublicKey<Secp256K1>) -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Prove over the ECDSA credential.
    let (verifier_data, proof) = make_ecdsa_proof::<F, C, D>(cred, iss_pk)?;

    // Set up the recursive proof.
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

    // Recursively verify the inner proof.
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