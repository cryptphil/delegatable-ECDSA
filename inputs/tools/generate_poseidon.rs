use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, PrimeField64};
use plonky2::field::goldilocks_field::GoldilocksField as GL;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use plonky2_ecdsa::curve::{
    ecdsa::ECDSASecretKey,
    secp256k1::Secp256K1,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use num_traits::Num;

#[derive(Parser)]
struct Args {
    /// Input file path (SHA512-mode recursive proof input)
    #[arg(short, long)]
    input: PathBuf,
    
    /// Output file path
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct Point {
    x: String,
    y: String,
}

#[derive(Deserialize, Serialize)]
struct Signature {
    r: String,
    s: String,
}

#[derive(Deserialize, Serialize)]
struct RecursiveInput {
    // Inner circuit fields (unchanged)
    pk_issuer: Point,
    msg: String,
    signature: Signature,
    pk_c: Point,
    sk_c: String,
    
    // Outer circuit fields (C5 will be modified)
    sk_0: String,
    pk_0: Point,
    cc_0: String,
    derivation_index: u32,
    pk_i: Point,
    
    // SHA512-specific field (will be removed for Poseidon)
    #[serde(skip_serializing_if = "Option::is_none")]
    cc_i: Option<String>,
}

/// Convert hex string to BigUint
fn hex_to_biguint(hex: &str) -> Result<BigUint> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    Ok(BigUint::from_str_radix(hex, 16)?)
}

/// Convert BigUint to hex string
fn biguint_to_hex(big: &BigUint) -> String {
    let mut s = big.to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}

/// Convert BigUint to 8×u32 limbs in LE order (matching generate.rs)
fn biguint_to_u32_limbs_le(big: &BigUint) -> [u32; 8] {
    let mut bytes = big.to_bytes_le();
    // Pad to 32 bytes (8×u32)
    bytes.resize(32, 0);
    
    let mut limbs = [0u32; 8];
    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        let mut chunk = [0u8; 4];
        chunk.copy_from_slice(&bytes[start..end]);
        limbs[i] = u32::from_le_bytes(chunk);
    }
    limbs
}

/// Convert u64 array to bytes (big-endian, matching generate.rs)
fn u64s_to_bytes(limbs: &[u64; 4]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &limb in limbs {
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    bytes
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("Converting SHA512-mode input to Poseidon-mode for C5 constraint");
    
    // Read input file
    let input_data = fs::read_to_string(&args.input)?;
    let mut input: RecursiveInput = serde_json::from_str(&input_data)?;
        
    // Parse pk_0 coordinates 
    let pk0_x = hex_to_biguint(&input.pk_0.x)?;
    let pk0_y = hex_to_biguint(&input.pk_0.y)?;
    
    // Prepare pk_0 coordinates as bytes (padded to 32 bytes)
    let mut pk0_x_bytes = pk0_x.to_bytes_be();
    let mut pk0_y_bytes = pk0_y.to_bytes_be();
    
    while pk0_x_bytes.len() < 32 { pk0_x_bytes.insert(0, 0); }
    while pk0_y_bytes.len() < 32 { pk0_y_bytes.insert(0, 0); }
    
    // Build Poseidon preimage: pk0.x (8×u32), pk0.y (8×u32), cc0 (8×u32), i (1)
    let mut inputs_gl: Vec<GL> = Vec::new();
    
    // pk0.x as 8×u32-Limbs (LE-order like NonNative-Target)
    for limb in biguint_to_u32_limbs_le(&BigUint::from_bytes_be(&pk0_x_bytes)) {
        inputs_gl.push(GL::from_canonical_u32(limb));
    }
    
    // pk0.y as 8×u32-Limbs (LE-order)
    for limb in biguint_to_u32_limbs_le(&BigUint::from_bytes_be(&pk0_y_bytes)) {
        inputs_gl.push(GL::from_canonical_u32(limb));
    }
    
    // cc0 as 8×u32-Limbs (LE-order) 
    let cc_0_bytes = hex::decode(input.cc_0.strip_prefix("0x").unwrap_or(&input.cc_0))?;
    let mut cc_0_bytes_32 = [0u8; 32];
    let len = cc_0_bytes.len().min(32);
    cc_0_bytes_32[32-len..].copy_from_slice(&cc_0_bytes[..len]);
    
    for limb in biguint_to_u32_limbs_le(&BigUint::from_bytes_be(&cc_0_bytes_32)) {
        inputs_gl.push(GL::from_canonical_u32(limb));
    }
    
    // derivation_index as Goldilocks-Element
    inputs_gl.push(GL::from_canonical_u32(input.derivation_index));

    // Poseidon-Hashing with domain separation (circuit-compatible)
    let mut w_inputs = inputs_gl.clone();
    w_inputs.push(GL::from_canonical_u32(0)); // domain_tag=0 for scalar w
    let w_hash = PoseidonHash::hash_no_pad(&w_inputs);
    
    // w-scalar directly from Poseidon-output (circuit-compatible)
    let w_u64s: [u64; 4] = [
        w_hash.elements[0].to_canonical_u64(),
        w_hash.elements[1].to_canonical_u64(),
        w_hash.elements[2].to_canonical_u64(),
        w_hash.elements[3].to_canonical_u64(),
    ];
    
    let w_scalar = Secp256K1Scalar::from_noncanonical_biguint(
        BigUint::from_bytes_be(&u64s_to_bytes(&w_u64s))
    );
    
    // Check for w=0 (very unlikely but possible)
    if w_scalar.is_zero() {
        return Err(anyhow::anyhow!("Poseidon derivation resulted in w=0; please retry with different index."));
    }

    // Parse sk_0 from input and recreate the public key point
    let sk_0_hex = input.sk_0.strip_prefix("0x").unwrap_or(&input.sk_0);
    let sk_0_biguint = BigUint::from_str_radix(sk_0_hex, 16)?;
    let sk_0_scalar = Secp256K1Scalar::from_noncanonical_biguint(sk_0_biguint);
    let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_scalar);
    let pk_0_point = sk_0.to_public().0;  // This gives us the correct point type

    // Verify that our reconstructed point matches the input coordinates
    let expected_x = biguint_to_hex(&pk_0_point.x.to_canonical_biguint());
    let expected_y = biguint_to_hex(&pk_0_point.y.to_canonical_biguint());
    if expected_x != input.pk_0.x || expected_y != input.pk_0.y {
        return Err(anyhow::anyhow!("pk_0 coordinates don't match sk_0! Expected: ({}, {}), Got: ({}, {})", 
            expected_x, expected_y, input.pk_0.x, input.pk_0.y));
    }

    // Child Key derivation: child_pk = pk_0 + w*G (exactly like generate.rs)
    let w_sk = ECDSASecretKey::<Secp256K1>(w_scalar);
    let w_point = w_sk.to_public().0;
    let child_pk = (pk_0_point.to_projective() + w_point.to_projective()).to_affine();
    
    // Update pk_i with correctly computed Poseidon-derived child key
    input.pk_i.x = biguint_to_hex(&child_pk.x.to_canonical_biguint());
    input.pk_i.y = biguint_to_hex(&child_pk.y.to_canonical_biguint());
        
    // Remove cc_i for Poseidon mode (no child chain code)
    input.cc_i = None;
    
    // Write output file
    let output_json = serde_json::to_string_pretty(&input)?;
    fs::write(&args.output, output_json)?;
    
    println!("Converted to Poseidon mode");
    println!("Output written to: {:?}", args.output);
    
    Ok(())
}