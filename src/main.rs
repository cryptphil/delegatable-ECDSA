mod proofs;
mod cred;
mod utils;

use plonky2::field::types::Field;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use std::time::{Instant, SystemTime};
use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegation::delegate::{build_delegation_circuit, prove_delegation_base, prove_delegation_step};
use crate::proofs::delegation::initialize::{build_init_delegation_circuit, prove_init_delegation};
use anyhow::Result;


fn main() -> Result<()> {
    // ---- Generics / config ----
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Choose how many recursive layers to build (excluding base).
    let num_layers: usize = 10;

    // ---- Build init-delegation circuit ----
    let t_build_init = Instant::now();
    let (init_cd, init_targets) = build_init_delegation_circuit::<F, C, D>()?;
    println!("Init circuit build time: {:.2?}", t_build_init.elapsed());

    // ---- Prove init-delegation  ----
    let issuer = generate_fixed_issuer_keypair();
    let signed = issue_fixed_dummy_credential(&issuer.sk)?;
    let t_prove_init = Instant::now();
    let init_proof = prove_init_delegation::<F, C, D>(&init_cd, &init_targets, &signed, &issuer.pk)?;
    println!("Init base proof time: {:.2?}", t_prove_init.elapsed());

    // ---- Build delegation (outer) circuit once ----
    let t_build_del = Instant::now();
    let (del_cd, _del_common, del_targets) = build_delegation_circuit::<F, C, D>(&init_cd.common);
    println!("Delegation circuit build time: {:.2?}", t_build_del.elapsed());

    // ---- Base delegation proof (level = 0) ----
    let t_prove_base_outer = Instant::now();
    let base_outer = prove_delegation_base::<F, C, D>(&del_cd, &del_targets, &init_cd, &init_proof.proof)?;
    println!("Base outer proof time: {:.2?}", t_prove_base_outer.elapsed());
    del_cd.verifier_data().verify(base_outer.clone())?;
    check_cyclic_proof_verifier_data(&base_outer, &del_cd.verifier_only, &del_cd.common)?;
    println!("Verified base outer | level = {}", base_outer.public_inputs[del_targets.level_idx]);

    // ---- Build N recursive layers ----
    let mut proofs = Vec::with_capacity(num_layers + 1);
    proofs.push(base_outer);

    for i in 0..num_layers {
        let t_step = Instant::now();
        let prev = proofs.last().unwrap();
        let next = prove_delegation_step::<F, C, D>(&del_cd, &del_targets, &init_cd, prev)?;
        println!("Delegation step {} proof time: {:.2?}", i + 1, t_step.elapsed());

        del_cd.verifier_data().verify(next.clone())?;
        check_cyclic_proof_verifier_data(&next, &del_cd.verifier_only, &del_cd.common)?;
        println!(
            "Verified step {:>2} | level = {}",
            i + 1,
            next.public_inputs[del_targets.level_idx]
        );

        proofs.push(next);
    }

    println!(
        "Constructed {} proofs total (including base). Final level = {}",
        proofs.len(),
        proofs.last().unwrap().public_inputs[del_targets.level_idx]
    );
    
    Ok(())
}
