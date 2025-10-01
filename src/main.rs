mod cred;
mod proofs;
mod utils;

use crate::cred::credential::{generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::{build_delegation_circuit, init_delegation, prove_delegation_step};
use anyhow::Result;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};


fn main() -> Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // Setup issuer key pair.
    let issuer = generate_issuer_keypair();
    // Issue a dummy credential signed by issuer
    let cred = issue_fixed_dummy_credential(&issuer.sk)?;

    let init_circuit = init_delegation::<F, Cfg, D>(&cred, &issuer.pk)?;
    init_circuit.verifier_data.verify(init_circuit.proof.clone())?;
    println!("Init delegation proof passed!");

    // Build delegation circuits for 4 levels of delegation.
    println!("Building 4 levels of delegation circuits...");
    let build_start = std::time::Instant::now();
    let del_circuit1 = build_delegation_circuit(&init_circuit.verifier_data, init_circuit.level_index_pis);
    let del_circuit2 = build_delegation_circuit(&del_circuit1.data.verifier_data(), del_circuit1.level_index_pis);
    let del_circuit3 = build_delegation_circuit(&del_circuit2.data.verifier_data(), del_circuit2.level_index_pis);
    let del_circuit4 = build_delegation_circuit(&del_circuit3.data.verifier_data(), del_circuit3.level_index_pis);
    println!("Generation time of 4 delegation circuits: {:?}", build_start.elapsed());

    let circuits = vec![&del_circuit1, &del_circuit2, &del_circuit3, &del_circuit4];
    let mut prev_proof = init_circuit.proof;

    for (i, c) in circuits.iter().enumerate() {
        println!("Starting delegation {}...", i + 1);
        let proof_start = std::time::Instant::now();
        let proof = prove_delegation_step(c, &prev_proof, &issuer.pk, c.level_index_pis)?;
        println!("Delegation {} proof time: {:?}", i + 1, proof_start.elapsed());

        if proof.public_inputs[c.level_index_pis].to_canonical_u64() != (i as u64 + 1) {
            panic!("Level index in public inputs is wrong!");
        }
        prev_proof = proof;
    }

    // TODO: Create a presentation proof where we provide knowledge of a delegation proof and create a proof of knowledge of the public key.

    Ok(())
}


