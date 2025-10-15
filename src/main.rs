mod proofs;
mod cred;
mod utils;

use anyhow::Result;
use std::time::Instant;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

use crate::cred::credential::{generate_fixed_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegation::initialize::{build_init_delegation_circuit, prove_init_delegation};
use crate::proofs::delegation::delegate::{build_delegation_circuit, prove_delegation_base, prove_delegation_step};
use crate::proofs::presentation::present::{build_presentation_circuit, prove_presentation};

fn main() -> Result<()> {
    // ---- Generics / config ----
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Choose how many recursive layers to build (excluding base).
    let num_layers: usize = 5;

    // ---- Build init-delegation circuit ----
    let t_build_init = Instant::now();
    let (init_cd, init_targets) = build_init_delegation_circuit::<F, C, D>()?;
    println!("Init circuit build time: {:.2?}", t_build_init.elapsed());

    // ---- Prove init-delegation  ----
    let issuer = generate_fixed_issuer_keypair();
    let signed = issue_fixed_dummy_credential(&issuer.sk)?;
    let t_prove_init = Instant::now();
    let init_proof = prove_init_delegation::<F, C, D>(&init_cd, &init_targets, &signed, &issuer.pk)?;
    println!("Init base proof time:  {:.2?}", t_prove_init.elapsed());

    // ---- Build delegation (outer) circuit once ----
    let t_build_del = Instant::now();
    let (del_cd, _del_common, del_targets) = build_delegation_circuit::<F, C, D>(&init_cd.common);
    println!("Delegation circuit build time: {:.2?}", t_build_del.elapsed());

    // ---- Build presentation (ZK) wrapper once ----
    let n_outer = del_targets.outer_pis.len();
    let t_build_pres = Instant::now();
    let (pres_cd, pres_t) = build_presentation_circuit::<F, C, D>(&del_cd.common, n_outer);
    println!("Presentation wrapper build time: {:.2?}", t_build_pres.elapsed());

    // Header for per-step timings
    println!(
        "{:<6} | {:>12} | {:>13} | {:>12} | {:>13} | {}",
        "step", "deleg_prove", "deleg_verify", "pres_prove", "pres_verify", "level"
    );

    // ---- Base delegation proof (level = 0) ----
    let t_prove_base = Instant::now();
    let base_outer = prove_delegation_base::<F, C, D>(&del_cd, &del_targets, &init_cd, &init_proof.proof)?;
    let dt_prove_base = t_prove_base.elapsed();

    let t_verify_base = Instant::now();
    del_cd.verifier_data().verify(base_outer.clone())?;
    check_cyclic_proof_verifier_data(&base_outer, &del_cd.verifier_only, &del_cd.common)?;
    let dt_verify_base = t_verify_base.elapsed();

    let t_pres_prove0 = Instant::now();
    let pres0 = prove_presentation::<F, C, D>(&pres_cd, &pres_t, &del_cd, &base_outer)?;
    let dt_pres_prove0 = t_pres_prove0.elapsed();

    let t_pres_verify0 = Instant::now();
    pres_cd.verify(pres0.clone())?;
    let dt_pres_verify0 = t_pres_verify0.elapsed();

    println!(
        "{:<6} | {:>10}ms | {:>11}ms | {:>10}ms | {:>11}ms | {}",
        0,
        dt_prove_base.as_millis(),
        dt_verify_base.as_millis(),
        dt_pres_prove0.as_millis(),
        dt_pres_verify0.as_millis(),
        base_outer.public_inputs[del_targets.level_idx]
    );

    // ---- Build N recursive layers ----
    let mut prev = base_outer;
    for i in 1..=num_layers {
        // delegation step i
        let t_prove = Instant::now();
        let next = prove_delegation_step::<F, C, D>(&del_cd, &del_targets, &init_cd, &prev)?;
        let dt_prove = t_prove.elapsed();

        let t_verify = Instant::now();
        del_cd.verifier_data().verify(next.clone())?;
        check_cyclic_proof_verifier_data(&next, &del_cd.verifier_only, &del_cd.common)?;
        let dt_verify = t_verify.elapsed();

        // presentation for step i
        let t_pres_prove = Instant::now();
        let pres = prove_presentation::<F, C, D>(&pres_cd, &pres_t, &del_cd, &next)?;
        let dt_pres_prove = t_pres_prove.elapsed();

        let t_pres_verify = Instant::now();
        pres_cd.verify(pres.clone())?;
        let dt_pres_verify = t_pres_verify.elapsed();

        println!(
            "{:<6} | {:>10}ms | {:>11}ms | {:>10}ms | {:>11}ms | {}",
            i,
            dt_prove.as_millis(),
            dt_verify.as_millis(),
            dt_pres_prove.as_millis(),
            dt_pres_verify.as_millis(),
            next.public_inputs[del_targets.level_idx]
        );

        prev = next;
    }

    println!(
        "Done. Final level = {}",
        prev.public_inputs[del_targets.level_idx]
    );

    Ok(())
}