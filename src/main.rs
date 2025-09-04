mod cred;
mod proofs;

use anyhow::Result;
use plonky2::{
    plonk::{
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

use proofs::ecdsa;
use crate::cred::generate::{delegate_credential, generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::delegate_recursive;

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let issuer = generate_issuer_keypair();

    let base_cred = issue_fixed_dummy_credential(&issuer.sk)?;

    // First, initialize delegation, i.e., "delegate" from Issuer to Holder.
    // Proves that pk_iss signed the base credential pk_base
    let (init_verifier_data, init_proof) = ecdsa::gen_init_delegation_proof::<F, C, D>(&base_cred, &issuer.pk)?;

    // Delegate from pk_base to pk_u1
    let delegated_cred = delegate_credential(&base_cred)?;

    let (_verifier_data, _proof) = delegate_recursive(&init_verifier_data, &init_proof, 10)?;

    Ok(())
}