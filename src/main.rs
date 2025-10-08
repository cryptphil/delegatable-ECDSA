mod proofs;
mod cred;
mod utils;

use plonky2::field::types::Field;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use std::time::SystemTime;

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Choose how many recursive layers you want to generate (excluding base).
    let num_layers: usize = 10; // change as needed

    // Build the circuit once and get targets for witness setting.
    let (circuit, common_data, targets) = build_delegation_circuit::<F, C, D>();
    println!("Constructed circuit in {}s", t0.elapsed().unwrap().as_secs());

    // Base public inputs: [initial, output] for the base case (output == initial when verify=false).
    let base_pis: [F; 2] = [F::ZERO, F::ZERO];

    // Create base + N layers.
    let t1 = SystemTime::now();
    let proofs = prove_delegations::<F, C, D>(&circuit, &common_data, &targets, &base_pis, num_layers)?;
    println!(
        "Constructed {} proofs (including base) in {}s",
        proofs.len(),
        t1.elapsed().unwrap().as_secs()
    );

    // Verify each proof as we go.
    for (i, proof) in proofs.iter().enumerate() {
        check_cyclic_proof_verifier_data(&proof, &circuit.verifier_only, &circuit.common)?;
        circuit.verify(proof.clone())?;
        if i == 0 {
            println!("Verified base proof.");
        } else {
            println!("Verified layer {} proof.", i);
        }
    }

    Ok(())
}
