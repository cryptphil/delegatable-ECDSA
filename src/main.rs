mod cred;
mod proofs;
mod utils;

use crate::cred::credential::{generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::proofs::delegate::init_delegate;
use anyhow::Result;


fn main() -> Result<()> {
    let issuer = generate_issuer_keypair();
    let cred = issue_fixed_dummy_credential(&issuer.sk)?;

    init_delegate(&cred, &issuer.pk)
}


