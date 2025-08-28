//! Outer circuit proof generation command.

use anyhow::Result;
use log::Level;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;
use std::{fs, path::Path, time::Instant};
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use crate::types::input::{FullInput, SignatureMode};
use crate::utils::parsing::{hex_to_bigint, hex_to_fixed_be_bytes, set_bytes_as_bits_be, set_u32_be_bits_non_hardened};
use crate::circuits::outer::{OuterCircuit, KeyDerivationTargets};
use crate::circuits::inner::InnerCircuit;
use crate::commands::inner::generate_inner_proof;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Convert chain code hex string to field elements (8×u32 limbs in LE order)
fn cc_hex_to_field_elements(cc_hex: &str) -> [F; 8] {
    use num_bigint::BigUint;
    let cc_bytes = hex::decode(&cc_hex[2..]).expect("Invalid cc hex");
    let big = BigUint::from_bytes_be(&cc_bytes);
    let mut le_bytes = big.to_bytes_le();
    le_bytes.resize(32, 0); // Pad to 32 bytes
    
    let mut out = [F::ZERO; 8];
    for i in 0..8 {
        let limb = u32::from_le_bytes(le_bytes[i*4..i*4+4].try_into().unwrap());
        out[i] = F::from_canonical_u32(limb);
    }
    out
}

/// Generate outer recursive proof (includes inner proof generation)
pub fn generate_outer_proof(
    inner: &InnerCircuit,
    outer: &OuterCircuit,
    input_file: &str,
    build_dir: &Path,
) -> Result<()> {
    let total_start = Instant::now();
    
    let inner_signature_mode_str = match outer.inner_signature_mode {
        SignatureMode::Static => "STATIC PK",
        SignatureMode::Dynamic => "DYNAMIC PK",
    };
    
    // First generate inner proof
    println!("=== INNER PROOF GENERATION ({}) ===", inner_signature_mode_str);
    generate_inner_proof(inner, input_file, build_dir)?;
    
    // Load the generated inner proof
    println!("\n=== OUTER RECURSIVE PROOF ===");
    println!("Loading inner proof artifacts...");
    let load_start = Instant::now();
    let inner_proof_data = fs::read(build_dir.join("inner_proof.bin"))?;
    let inner_proof: plonky2::plonk::proof::ProofWithPublicInputs<F, Cfg, D> = 
        bincode::deserialize(&inner_proof_data)?;
    println!("Inner proof load + deserialization time: {:?}", load_start.elapsed());
    
    // Load input data
    println!("Loading outer input data from: {}", input_file);
    let input_data = fs::read_to_string(input_file)?;
    let input: FullInput = serde_json::from_str(&input_data)?;
    
    println!("Setting up outer circuit witness...");
    let witness_start = Instant::now();
        
    // Parse parent data for BIP32 Key Derivation (C5)
    let pk_0_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.x));
    let pk_0_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_0.y));
    
    // Parse pk_issuer for consistency check
    let pk_issuer_x = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.x));
    let pk_issuer_y = P256Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_issuer.y));
    
    // Parse parent chain code
    let cc_0 = hex_to_fixed_be_bytes::<32>(&input.cc_0);
    
    // Parse derivation index
    let derivation_index = input.derivation_index;
    
    // Parse expected child outputs (should be public inputs per your design)
    let pk_i_x = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.x));
    let pk_i_y = Secp256K1Scalar::from_noncanonical_biguint(hex_to_bigint(&input.pk_i.y));
    
    let cc_i = match &input.cc_i {
        Some(cc_i_str) => hex_to_fixed_be_bytes::<32>(cc_i_str),
        None => [0u8; 32], // Default for Poseidon mode (not used)
    };
    
    // ===== SET UP CIRCUIT WITNESSES =====
    
    let mut pw = PartialWitness::<F>::new();
    
    // Set recursive proof data - verifies inner proof (C1-C4)
    pw.set_proof_with_pis_target(&outer.targets.proof, &inner_proof)?;
    pw.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
    
    // Set pk_issuer witness (public input in outer circuit)
    pw.set_biguint_target(&outer.targets.pk_issuer.x.value, &pk_issuer_x.to_canonical_biguint())?;
    pw.set_biguint_target(&outer.targets.pk_issuer.y.value, &pk_issuer_y.to_canonical_biguint())?;
        
    // Set derivation witnesses (mode-specific)
    match &outer.targets.key_derivation_targets {
        KeyDerivationTargets::Bip32(bip32_targets) => {
            println!("Setting SHA512-based BIP32 witnesses...");
            
            // Set parent public key (private input)
            pw.set_biguint_target(&bip32_targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
            pw.set_biguint_target(&bip32_targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
            
            // Set expected child public key
            pw.set_biguint_target(&bip32_targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
            pw.set_biguint_target(&bip32_targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
            
            // Set parent chain code (256 bits as BoolTargets)
            set_bytes_as_bits_be(
                &mut pw,
                &bip32_targets.cc_0,
                &cc_0,
            )?;
            
            // Set child index (32 bits, non-hardened enforced)
            set_u32_be_bits_non_hardened(
                &mut pw,
                &bip32_targets.derivation_index,
                derivation_index,
            )?;
            
            // Set expected child chain code (256 bits as BoolTargets)
            set_bytes_as_bits_be(
                &mut pw,
                &bip32_targets.cc_i,
                &cc_i,
            )?;
        }
        KeyDerivationTargets::Poseidon(poseidon_targets) => {
            println!("Setting Poseidon-based key derivation witnesses...");
            
            // Set parent public key (private input)
            pw.set_biguint_target(&poseidon_targets.pk_0.x.value, &pk_0_x.to_canonical_biguint())?;
            pw.set_biguint_target(&poseidon_targets.pk_0.y.value, &pk_0_y.to_canonical_biguint())?;
            
            // Set expected child public key
            pw.set_biguint_target(&poseidon_targets.pk_i.x.value, &pk_i_x.to_canonical_biguint())?;
            pw.set_biguint_target(&poseidon_targets.pk_i.y.value, &pk_i_y.to_canonical_biguint())?;
            
            // Set parent chain code (8×u32 field elements)
            let cc_0_fields = cc_hex_to_field_elements(&input.cc_0);
            for (target, &field_val) in poseidon_targets.cc_0.iter().zip(cc_0_fields.iter()) {
                let _ = pw.set_target(*target, field_val);
            }
            
            // Set derivation index (single field element)
            let _ = pw.set_target(poseidon_targets.derivation_index, F::from_canonical_u32(derivation_index));
            
            // Note: No cc_i for Poseidon mode (no chain code output)
        }
    }
    
    println!("Outer witness setup time: {:?}", witness_start.elapsed());
    
    // Generate outer recursive proof
    println!("Generating outer recursive proof (Inner: {})...", inner_signature_mode_str);
    let mut timing = TimingTree::new("outer_recursive_proof", Level::Info);
    let proof = prove(&outer.data.prover_only, &outer.data.common, pw, &mut timing)?;
    println!("Outer recursive proof timing breakdown:");
    timing.print();
    println!("Outer recursive proof size: {} bytes", proof.to_bytes().len());
    
    // Verify outer recursive proof
    println!("Verifying outer recursive proof...");
    let verify_start = Instant::now();
    outer.data.verify(proof.clone())?;
    println!("Outer recursive proof verification time: {:?}", verify_start.elapsed());
        
    // Save outer proof, verifier data, and common data
    println!("Serializing and saving outer proof artifacts...");
    let save_start = Instant::now();
    
    // Save proof
    let outer_proof_data = bincode::serialize(&proof)?;
    fs::write(build_dir.join("outer_proof.bin"), &outer_proof_data)?;
    println!("Outer proof saved: {} bytes", outer_proof_data.len());
    
    // Save verifier data
    let verifier_data = bincode::serialize(&outer.data.verifier_only)?;
    fs::write(build_dir.join("outer_verifier.bin"), &verifier_data)?;
    println!("Outer verifier data saved: {} bytes", verifier_data.len());
    
    // Save common circuit data
    let common_data = bincode::serialize(&outer.data.common)?;
    fs::write(build_dir.join("outer_common.bin"), &common_data)?;
    println!("Outer common data saved: {} bytes", common_data.len());
    
    println!("Outer proof serialization + save time: {:?}", save_start.elapsed());
    
    println!("\n=== PERFORMANCE SUMMARY ===");
    println!("Total recursive proof system time: {:?}", total_start.elapsed());
    println!("=== OUTER UNIFIED RECURSIVE PROOF COMPLETE (Inner: {}) ===", inner_signature_mode_str);
    
    Ok(())
}