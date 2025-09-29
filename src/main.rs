mod cred;
mod proofs;
mod utils;

use crate::cred::credential::{generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::{init_delegation, prove_delegation_step};
use anyhow::Result;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
// fn main() -> Result<()> {
//     const D: usize = 2;
//     type C = PoseidonGoldilocksConfig;
//     type F = <C as GenericConfig<D>>::F;
//
//     // Setup issuer key pair.
//     let issuer = generate_issuer_keypair();
//     // Issue a dummy credential signed by issuer
//     let cred = issue_fixed_dummy_credential(&issuer.sk)?;
//
//     // First, initialize delegation, i.e., "delegate" from Issuer to Holder.
//     // Proves that pk_iss signed the base credential pk_base
//     let (init_verifier_data, init_proof) = ecdsa::make_ecdsa_proof::<F, C, D>(&cred, &issuer.pk)?;
//
//     // Delegate from pk_base to pk_u1
//     let delegated_cred = delegate_credential(&cred)?;
//
//     // Prove delegation step
//     let (_verifier_data, _proof) = prove_delegation_step(&init_verifier_data, &init_proof, &delegated_cred)?;
//
//     Ok(())
// }

fn main() -> Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    // Setup issuer key pair.
    let issuer = generate_issuer_keypair();
    // Issue a dummy credential signed by issuer
    let cred = issue_fixed_dummy_credential(&issuer.sk)?;

    let (proof, verifier_data) = init_delegation::<F, Cfg, D>(&cred, &issuer.pk)?;

    verifier_data.verify(proof.clone())?;
    println!("Init delegation proof passed!");

    prove_delegation_step(&verifier_data, &proof, &cred)?;

    // TODO:
    // init delegate
    // then, delegate to another public key while setting L=L+1
    // finally, delegate to the final public key while setting L=L+1

    // Create a presentation proof where we provide knowledge of a delegation proof and create a proof of knowledge of the public key.


    Ok(())
}


