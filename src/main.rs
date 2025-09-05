mod cred;
mod proofs;
mod utils;

use crate::cred::generate::{generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::init_delegate;
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let issuer = generate_issuer_keypair();
    let cred = issue_fixed_dummy_credential(&issuer.sk)?;

    init_delegate(&cred, &issuer.pk)
}