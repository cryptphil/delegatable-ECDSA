use crate::cred::credential::CredentialData;
use crate::utils::parsing::{bits_to_hex, bits_to_string, find_field_bit_indices};
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_sha256::circuit::Sha256Targets;
use sha2::{Digest, Sha256};

/// Container for the compiled SHA256 circuit and its relevant targets.
pub struct Sha256Circuit {
    pub targets: Sha256Targets, // The message and digest targets.
    pub rev_idx: usize,        // The bit index where the revealed window section.
    pub rev_num_bytes: usize,  // Number of bytes revealed.
}


/// Build and prove a SHA256 circuit for a message of arbitrary length with a fixed reveal section.
///
/// - `msg_bits`: full message bits (MSB-first per byte)
/// - `digest_bits`: 256-bit SHA256 digest (MSB-first)
/// - `rev_idx`: first bit index to reveal (0-based)
/// - `rev_num_bytes`: number of bytes to reveal (0 = reveal nothing)
pub fn make_sha256_proof<F, Cfg, const D: usize>(
    msg_bits: &[bool],
    digest_bits: &[bool],
    rev_idx: usize,
    rev_num_bytes: usize,
) -> Result<(VerifierCircuitData<F, Cfg, D>, ProofWithPublicInputs<F, Cfg, D>)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut pw = PartialWitness::new();

    let circuit = make_sha256_circuit::<F, D>(&mut builder, msg_bits.len(), rev_idx, rev_num_bytes);

    let build_start = std::time::Instant::now();
    let data = builder.build::<Cfg>();
    println!("SHA256 circuit generation time: {:?}", build_start.elapsed());

    fill_sha256_circuit_witness::<F, Cfg, D>(&circuit, &mut pw, msg_bits, digest_bits)?;

    let prove_start = std::time::Instant::now();
    let proof = data.prove(pw)?;
    println!("SHA256 proof generation time: {:?}", prove_start.elapsed());

    Ok((data.verifier_data(), proof))
}


/// Add the SHA-256 circuit constrains for a message of `msg_len_bits` bits and a fixed reveal section.
///
/// - `rev_idx` is a bit index (0-based) where the revealed section start.
/// - `rev_num_bytes` is how many bytes to reveal starting from the rev_idx (0 == reveal nothing).
fn make_sha256_circuit<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_bits: usize,
    rev_idx: usize,
    rev_num_bytes: usize,
) -> Sha256Circuit
where
    F: RichField + Extendable<D>,
{
    assert_eq!(msg_len_bits % 8, 0, "message length must be whole bytes (bits multiple of 8)");
    assert!(rev_idx <= msg_len_bits, "rev_idx out of bounds");
    assert!(rev_num_bytes <= msg_len_bits / 8, "rev_num_bytes out of bounds");
    assert!(rev_idx + rev_num_bytes * 8 <= msg_len_bits, "reveal range exceeds message");

    let targets = plonky2_sha256::circuit::make_circuits(builder, msg_len_bits as u64);

    // Register revealed bytes as public inputs (if any).
    // We register revealed bytes first (byte order), each byte as 8 bits MSB-first.
    if rev_num_bytes > 0 {
        for byte_offset in 0..rev_num_bytes {
            let bit_base = rev_idx + byte_offset * 8;
            for bit_in_byte in 0..8 {
                let idx = bit_base + bit_in_byte;
                builder.register_public_input(targets.message[idx].target);
            }
        }
    }

    // Register digest bits as public input.
    for db in &targets.digest {
        builder.register_public_input(db.target);
    }

    Sha256Circuit {
        targets,
        rev_idx,
        rev_num_bytes,
    }
}

/// Fills the witness for a previously-built SHA256 circuit.
///
/// - `msg_bits`: message bits, length must match the circuit's message size (in bits)
/// - `digest_bits`: 256-bit SHA256 digest bits
pub fn fill_sha256_circuit_witness<F, Cfg, const D: usize>(
    circuit: &Sha256Circuit,
    pw: &mut PartialWitness<F>,
    msg_bits: &[bool],
    digest_bits: &[bool],
) -> Result<()>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let msg_len = msg_bits.len();
    assert_eq!(msg_len % 8, 0, "message length must be whole bytes (bits multiple of 8)");
    assert_eq!(digest_bits.len(), 256, "digest must be 256 bits");

    // Fill message bits.
    for i in 0..msg_len {
        pw.set_bool_target(circuit.targets.message[i], msg_bits[i])?;
    }

    // Fill digest bits.
    for (i, &b) in digest_bits.iter().enumerate() {
        pw.set_bool_target(circuit.targets.digest[i], b)?;
    }

    Ok(())
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

    let rev_str = bits_to_string(&bits[..rev_num_bytes * 8]);
    println!("Recovered public input: {}", rev_str);

    // Digest is next 256 bits
    let digest_bits = &bits[rev_num_bytes * 8..rev_num_bytes * 8 + 256];
    let digest_hex = bits_to_hex(digest_bits);
    println!("Recovered digest (hex): {}", digest_hex);
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

    // Create the proof.
    let (vcd, proof) = make_sha256_proof::<F, Cfg, D>(&msg_bits, &digest_bits, rev_idx, rev_num_bytes)?;

    // Verify the proof
    vcd.verify(proof.clone())?;

    // Print the revealed public inputs and digest.
    print_public_inputs::<F, Cfg, D>(&proof, rev_num_bytes);

    Ok(())
}


