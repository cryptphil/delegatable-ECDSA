use crate::cred::credential::CredentialData;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use sha2::{Digest, Sha256};


pub fn prove_sha256<F, Cfg, const D: usize>(msg: &[u8]) -> anyhow::Result<ProofWithPublicInputs<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    println!("Hash: {:#04X}", hash);

    let msg_bits = plonky2_sha256::circuit::array_to_bits(msg);
    let len = msg.len() * 8;
    println!("SHA256 block count: {}", (len + 65 + 511) / 512);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = plonky2_sha256::circuit::make_circuits(&mut builder, len as u64);
    let mut pw = PartialWitness::new();

    for i in 0..len {
        pw.set_bool_target(targets.message[i], msg_bits[i])?;
    }

    let expected_res = plonky2_sha256::circuit::array_to_bits(hash.as_slice());
    for i in 0..expected_res.len() {
        if expected_res[i] {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }

    println!(
        "Constructing SHA256 proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<Cfg>();
    let proof_start = std::time::Instant::now();
    let proof = data.prove(pw)?;
    println!("SHA256 proof time: {:?}", proof_start.elapsed());

    data.verify(proof.clone())?;
    Ok(proof)
}

#[test]
fn test_sha256_proof_hello() -> anyhow::Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let msg = b"Hello, world!";
    let proof = prove_sha256::<F, Cfg, D>(msg);

    if proof.is_ok() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("SHA256 proof failed"))
    }
}

#[test]
fn test_sha256_proof_credential() -> anyhow::Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let credential = CredentialData {
        cred_pk_sec1_compressed: "".to_string(),
        delegation_level: 0,
        name: "Alice".to_string(),
        address: "Musterstraße".to_string(),
        birthdate: "01.01.1999".to_string(),
    };
    let cred_bytes = serde_json::to_vec(&credential)?;

    let proof = prove_sha256::<F, Cfg, D>(cred_bytes.as_slice());

    if proof.is_ok() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("SHA256 proof failed"))
    }
}