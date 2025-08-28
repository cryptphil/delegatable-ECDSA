//! Inner circuit proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use std::{fs, path::Path, time::Instant};
use plonky2::field::types::{PrimeField, Field};
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::{FullInput, SignatureMode};
use crate::utils::parsing::{hex_to_bigint, set_nonnative_target};
use crate::circuits::inner::InnerCircuit;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Generate inner circuit proof with configurable signature verification mode
pub fn generate_inner_proof(
    inner: &InnerCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let signature_mode_str = match inner.signature_mode {
        SignatureMode::Static => "STATIC PK",
        SignatureMode::Dynamic => "DYNAMIC PK",
    };
    
    println!("=== INNER CIRCUIT: C1-C4 ({}) ===", signature_mode_str);
    println!("Loading inner input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInput = serde_json::from_str(&input_data)?;
    
    let start = Instant::now();
    
    // Parse EUDI (P-256) inputs - C1+C2: Key Derivation, C3: Signature Verification  
    let pk_c_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.x));
    let pk_c_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_c.y));
    let sk_c = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_c));
    let msg = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.msg));
    let sig_r = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.r));
    let sig_s = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.signature.s));
    
    // C4: Parse secp256k1 inputs
    let sk_0 = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.sk_0));
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Set up inner circuit witness
    println!("Setting up inner circuit witness ({})...", signature_mode_str);
    let mut pw = PartialWitness::<F>::new();
    
    // C1+C2: EUDI Key Derivation (P256) witness data
    pw.set_biguint_target(&inner.targets.pk_c.x.value, &pk_c_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_c.y.value, &pk_c_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.sk_c, sk_c)?;
    
    // C3: Signature Verification witness data
    set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.r, sig_r)?;
    set_nonnative_target(&mut pw, &inner.targets.sig.s, sig_s)?;
    
    // C3: Set pk_issuer (always present now, validated in static mode)
    let pk_issuer = &input.pk_issuer;
    let pk_issuer_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&pk_issuer.x));
    let pk_issuer_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&pk_issuer.y));
    pw.set_biguint_target(&inner.targets.pk_issuer.x.value, &pk_issuer_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_issuer.y.value, &pk_issuer_y.to_canonical_biguint())?;
    
    // C4: Secp256k1 Key Derivation witness data
    pw.set_biguint_target(&inner.targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
    pw.set_biguint_target(&inner.targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
    set_nonnative_target(&mut pw, &inner.targets.sk_0, sk_0)?;
        
    // Generate inner proof
    println!("Generating inner proof ({})...", signature_mode_str);
    let mut timing = TimingTree::new("inner_proof", Level::Info);
    let proof = prove(&inner.data.prover_only, &inner.data.common, pw, &mut timing)?;
    println!("Inner proof timing breakdown:");
    timing.print();
    println!("Inner proof size: {} bytes", proof.to_bytes().len());
    
    // Verify inner proof
    println!("Verifying inner proof ({})...", signature_mode_str);
    let verify_start = Instant::now();
    inner.data.verify(proof.clone())?;
    println!("Inner proof verification time: {:?}", verify_start.elapsed());
    
    // Save inner proof, verifier data, and common data
    println!("Serializing and saving inner proof artifacts...");
    let save_start = Instant::now();
    
    // Save proof
    let proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("inner_proof.bin"), &proof_data)?;
    println!("Inner proof saved: {} bytes", proof_data.len());
    
    // Save verifier data
    let verifier_data = bincode::serialize(&inner.data.verifier_only)?;
    fs::write(build_dir.join("inner_verifier.bin"), &verifier_data)?;
    println!("Inner verifier data saved: {} bytes", verifier_data.len());
    
    // Save common circuit data
    let common_data = bincode::serialize(&inner.data.common)?;
    fs::write(build_dir.join("inner_common.bin"), &common_data)?;
    println!("Inner common data saved: {} bytes", common_data.len());
    
    println!("Inner proof serialization + save time: {:?}", save_start.elapsed());
    
    let inner_total = start.elapsed();
    println!("Inner circuit total time: {:?}", inner_total);
    println!("=== INNER UNIFIED CIRCUIT COMPLETE ({}) ===", signature_mode_str);
    
    Ok(())
}