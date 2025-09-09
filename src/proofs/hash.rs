use crate::cred::credential::CredentialData;
use crate::utils::parsing::find_field_bit_indices;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use sha2::{Digest, Sha256};

/// Prove over a SHA256 message hash with optional selective disclosure of bytes of the preimage.
///
/// - `msg`: full message bits (MSB-first per byte)
/// - `digest`: 256-bit SHA256 digest (MSB-first)
/// - `rev_idx`: first bit index to reveal (0-based)
/// - `rev_num_bytes`: number of bytes to reveal (0 = reveal nothing)
pub fn prove_sha256_sel_disclosure<F, Cfg, const D: usize>(
    msg: &[bool],
    digest: &[bool],
    rev_idx: usize,
    rev_num_bytes: usize,
) -> Result<ProofWithPublicInputs<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let msg_len = msg.len();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = plonky2_sha256::circuit::make_circuits(&mut builder, msg_len as u64);

    // Optionally register disclosed bytes as public inputs.
    if rev_num_bytes > 0 {
        for byte_offset in 0..rev_num_bytes {
            for bit_in_byte in 0..8 {
                let idx = rev_idx + byte_offset * 8 + bit_in_byte;
                builder.register_public_input(targets.message[idx].target);
            }
        }
    }

    // Digest is always a public input.
    for bit in &targets.digest {
        builder.register_public_input(bit.target);
    }

    let mut pw = PartialWitness::new();

    // Fill message bits.
    for (i, &b) in msg.iter().enumerate() {
        pw.set_bool_target(targets.message[i], b)?;
    }

    // Constrain digest to match the expected digest.
    for (i, &b) in digest.iter().enumerate() {
        pw.set_bool_target(targets.digest[i], b)?;
    }

    let data = builder.build::<Cfg>();
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok(proof)
}


/// Convenience wrapper: prove SHA256 without revealing any part of the message.
pub fn prove_sha256_no_reveal<F, Cfg, const D: usize>(
    msg: &[bool],
    digest: &[bool],
) -> anyhow::Result<ProofWithPublicInputs<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    // rev_num_bytes = 0 → nothing revealed
    prove_sha256_sel_disclosure(msg, digest, 0, 0)
}

/// Print the revealed public inputs and the digest from the proof.
///
/// `rev_num_bytes`: number of revealed bytes (0 = none)
fn print_public_inputs<F, Cfg, const D: usize>(
    proof: &ProofWithPublicInputs<F, Cfg, D>,
    rev_num_bytes: usize,
)
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let bits: Vec<bool> = proof
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64() != 0) // field -> bool
        .collect();

    let rev_bytes: Vec<u8> = bits.chunks(8)
        .take(rev_num_bytes)
        .map(|chunk| {
            let mut val = 0u8;
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    val |= 1 << (7 - i); // MSB first
                }
            }
            val
        })
        .collect();

    let rev_str = String::from_utf8_lossy(&rev_bytes);
    println!("Recovered public input: {}", rev_str);

    // Digest is next 256 bits
    let digest_bits = &bits[rev_num_bytes * 8..rev_num_bytes * 8 + 256];
    let mut digest_bytes = vec![0u8; 32];

    for (i, chunk) in digest_bits.chunks(8).enumerate() {
        let mut val = 0u8;
        for (j, bit) in chunk.iter().enumerate() {
            if *bit {
                val |= 1 << (7 - j);
            }
        }
        digest_bytes[i] = val;
    }
    println!("Recovered digest (hex): {}", hex::encode(digest_bytes));
}

#[test]
fn test_sha256_proof_rev_name() -> Result<()> {
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

    // Serialize the credential.
    let cred_json = credential.to_json()?;
    let cred_bytes = credential.to_json_bytes()?;
    let msg_bits = plonky2_sha256::circuit::array_to_bits(&cred_bytes);

    // Get the index and length of the "name" field in bits.
    let (rev_idx, rev_num_bytes) = find_field_bit_indices(&cred_json, "name")?;
    println!("Revealing 'name' field bits: {} to {}", rev_idx, rev_num_bytes);

    // Compute SHA256 digest of the full credential.
    let mut hasher = Sha256::new();
    hasher.update(&cred_bytes);
    let digest_bytes = hasher.finalize();
    let digest_bits = plonky2_sha256::circuit::array_to_bits(digest_bytes.as_slice());
    println!("Digest (hex): {}", hex::encode(digest_bytes));


    let proof = prove_sha256_sel_disclosure::<F, Cfg, D>(&msg_bits, &digest_bits, rev_idx, rev_num_bytes)?;

    print_public_inputs::<F, Cfg, D>(&proof, rev_num_bytes);

    Ok(())
}

