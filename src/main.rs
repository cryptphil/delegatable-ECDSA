mod cred;
mod proofs;
mod utils;

use crate::cred::credential::{inital_delegation, generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::gen_delegation_proof;
use crate::proofs::ecdsa;
use anyhow::Result;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Setup issuer key pair.
    let issuer = generate_issuer_keypair();
    // Issue a dummy credential signed by issuer
    let cred = issue_fixed_dummy_credential(&issuer.sk)?;

    // First, initialize delegation, i.e., "delegate" from Issuer to Holder.
    // Proves that pk_iss signed the base credential pk_base
    let (init_verifier_data, init_proof) = ecdsa::gen_ecdsa_proof::<F, C, D>(&cred, &issuer.pk)?;

    // Delegate from pk_base to pk_u1
    let delegated_cred = inital_delegation(&cred)?;

    // Prove delegation step
    let (_verifier_data, _proof) = gen_delegation_proof(&init_verifier_data, &init_proof, &delegated_cred)?;

    Ok(())
}


