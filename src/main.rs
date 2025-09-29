mod cred;
mod proofs;
mod utils;

use crate::cred::credential::{generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::{build_delegation_circuit, init_delegation, prove_delegation_step};
use anyhow::Result;
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

    let first_del_circuit = build_delegation_circuit(&init_circuit.verifier_data, init_circuit.level_index_pis);

    // First delegation.
    let (proof1, verifier1) = prove_delegation_step(&first_del_circuit, &init_circuit.proof, &issuer.pk, init_circuit.level_index_pis)?;
    first_del_circuit.data.verify(proof1.clone())?;
    println!("Recursive proof (layer {}) passed!", proof1.public_inputs[first_del_circuit.level_index_pis]);

    // This delegation circuit can be used fo all further delegation steps.
    let del_circuit = build_delegation_circuit(&verifier1, first_del_circuit.level_index_pis);

    // Second delegation.
    let (proof2, _verifier2) = prove_delegation_step(&del_circuit, &proof1, &issuer.pk, del_circuit.level_index_pis)?;
    del_circuit.data.verify(proof2.clone())?;
    println!("Recursive proof (layer {}) passed!", proof2.public_inputs[del_circuit.level_index_pis]);

    // TODO: Third delegation does not work yet.
    // let (proof3, _verifier3) = prove_delegation_step(&del_circuit, &proof2, &issuer.pk, del_circuit.level_index_pis)?;
    // del_circuit.data.verify(proof3.clone())?;
    // println!("Recursive proof (layer {}) passed!", proof3.public_inputs[del_circuit.level_index_pis]);


    // TODO: Create a presentation proof where we provide knowledge of a delegation proof and create a proof of knowledge of the public key.

    Ok(())
}


