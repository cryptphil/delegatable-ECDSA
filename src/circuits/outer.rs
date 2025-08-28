//! Outer circuit implementation for recursive verification and BIP32 key derivation.
//!
//! This module implements the outer circuit (C5) that:
//! - Recursively verifies the inner proof (C1-C4)
//! - Performs BIP32 non-hardened key derivation with SHA512 or Poseidon
//! - Ensures consistency between inner and outer circuits

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints_fixed, Bip32KeyDerivationTargets,
    add_poseidon_key_derivation_constraints, PoseidonKeyDerivationTargets,
};
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};
use crate::types::input::{SignatureMode, DerivationMode};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Key derivation targets (mode-dependent)
#[allow(dead_code)]
pub enum KeyDerivationTargets {
    Bip32(Bip32KeyDerivationTargets),
    Poseidon(PoseidonKeyDerivationTargets),
}

/// Targets for the outer circuit.
#[allow(dead_code)]
pub struct OuterCircuitTargets {
    // Recursive verification targets
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    
    // pk_issuer consistency check target
    pub pk_issuer: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    
    // Key Derivation targets (mode-dependent)
    pub key_derivation_targets: KeyDerivationTargets,
}

/// Outer circuit that recursively verifies the inner proof and performs BIP32 key derivation.
#[allow(dead_code)]
pub struct OuterCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterCircuitTargets,
    pub inner_signature_mode: SignatureMode,
    pub derivation_mode: DerivationMode,
}

/// Build the outer circuit that recursively verifies the inner proof
/// and performs BIP32 non-hardened key derivation.
/// This circuit always implements:
/// - Recursive verification of inner proof (C1-C4)
/// - C5: BIP32 non-hardened key derivation: pk_i = KeyDer(pk_0, cc_0, i)
pub fn build_outer_circuit(
    inner_common: &CommonCircuitData<F, D>,
    inner_signature_mode: SignatureMode,
    derivation_mode: DerivationMode,
) -> OuterCircuit {
    build_outer_circuit_with_optimization(inner_common, inner_signature_mode, derivation_mode)
}

/// Build the outer circuit with optional HMAC-SHA512 optimization
pub fn build_outer_circuit_with_optimization(
    inner_common: &CommonCircuitData<F, D>,
    inner_signature_mode: SignatureMode,
    derivation_mode: DerivationMode,
) -> OuterCircuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // === Recursive Proof Verification ===
    // Add targets for the proof of the inner circuit and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    // === pk_0 Consistency Check ===
    // Ensure the same pk_0 is used in both outer and inner circuits
    // This prevents malicious users from using different keys
    
    // Add pk_0 as private input to outer circuit
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    // Extract pk_0 from inner circuit's public inputs (first 8 field elements)
    // Inner circuit registers pk_0 as: x_limbs (4) + y_limbs (4) = 8 field elements total
    let inner_pk_0_x_limbs = [
        proof.public_inputs[0],
        proof.public_inputs[1], 
        proof.public_inputs[2],
        proof.public_inputs[3],
    ];
    let inner_pk_0_y_limbs = [
        proof.public_inputs[4],
        proof.public_inputs[5],
        proof.public_inputs[6], 
        proof.public_inputs[7],
    ];
    
    // Connect outer private pk_0 with inner public pk_0
    for (outer_limb, &inner_limb) in pk_0.x.value.limbs.iter().zip(inner_pk_0_x_limbs.iter()) {
        builder.connect(outer_limb.0, inner_limb);
    }
    for (outer_limb, &inner_limb) in pk_0.y.value.limbs.iter().zip(inner_pk_0_y_limbs.iter()) {
        builder.connect(outer_limb.0, inner_limb);
    }

    // === pk_issuer Consistency ===
    // Register inner proof's pk_issuer directly as outer circuit public inputs
    
    // Extract pk_issuer from inner circuit's public inputs (positions 8-15)
    let inner_pk_issuer_x_limbs = [
        proof.public_inputs[8], proof.public_inputs[9], 
        proof.public_inputs[10], proof.public_inputs[11],
    ];
    let inner_pk_issuer_y_limbs = [
        proof.public_inputs[12], proof.public_inputs[13],
        proof.public_inputs[14], proof.public_inputs[15],
    ];
    
    // Register inner proof's pk_issuer as outer public inputs (pass-through)
    for &limb in inner_pk_issuer_x_limbs.iter().chain(inner_pk_issuer_y_limbs.iter()) {
        builder.register_public_input(limb);
    }
    
    // Create pk_issuer target for witness setting (not constrained)
    let pk_issuer = builder.add_virtual_affine_point_target::<P256>();

    // === C5: Key Derivation ===
    // Implement key derivation: pk_i = KeyDer(pk_0, cc_0, i)
    let key_derivation_targets = match derivation_mode {
        DerivationMode::Sha512 => {
            println!("Using optimized fixed-shape HMAC-SHA512 for BIP32 derivation...");
            let targets = add_bip32_key_derivation_constraints_fixed(&mut builder);
            
            // === SHA512-specific Public Inputs Registration (Bit Packing) ===
            println!("SHA512 mode: Packing bits into field elements for public inputs...");
            
            // Pack cc_0 (256 bits) into 8 field elements
            let cc_0_packed = pack_256_bits_to_field_elements(&targets.cc_0, &mut builder);
            for &target in &cc_0_packed {
                builder.register_public_input(target);
            }
            
            // Pack derivation_index (32 bits) into 1 field element  
            let index_packed = pack_32_bits_to_field_element(&targets.derivation_index, &mut builder);
            builder.register_public_input(index_packed);
            
            // Register pk_i as public input
            for limb in targets.pk_i.x.value.limbs.iter().chain(
                targets.pk_i.y.value.limbs.iter()
            ) {
                builder.register_public_input(limb.0);
            }
            
            // Pack cc_i (256 bits) into 8 field elements
            let cc_i_packed = pack_256_bits_to_field_elements(&targets.cc_i, &mut builder);
            for &target in &cc_i_packed {
                builder.register_public_input(target);
            }
            
            KeyDerivationTargets::Bip32(targets)
        }
        DerivationMode::Poseidon => {
            println!("Poseidon mode: Using field-native key derivation...");
            let targets = add_poseidon_key_derivation_constraints(&mut builder);
            
            // === Poseidon-specific Public Inputs Registration (Field-Native) ===
            println!("Poseidon mode: Field-native public inputs...");
            
            // cc_0 is already field elements (8×u32 limbs)
            for &cc_limb in targets.cc_0.iter() {
                builder.register_public_input(cc_limb);
            }
            
            // derivation_index is already a field element
            builder.register_public_input(targets.derivation_index);
            
            // Register pk_i as public input (8×u32 limbs for x and y)
            for limb in targets.pk_i.x.value.limbs.iter().chain(
                targets.pk_i.y.value.limbs.iter()
            ) {
                builder.register_public_input(limb.0);
            }
                        
            KeyDerivationTargets::Poseidon(targets)
        }
    };
        
    let data = builder.build::<Cfg>();
    let targets = OuterCircuitTargets {
        proof,
        vd,
        pk_issuer,
        key_derivation_targets,
    };
    
    OuterCircuit { 
        data, 
        targets, 
        inner_signature_mode,
        derivation_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::inner::build_inner_circuit;
    
    #[test]
    fn test_build_outer_circuit_with_static_inner_sha512() {
        let inner = build_inner_circuit(SignatureMode::Static);
        let outer = build_outer_circuit(&inner.data.common, SignatureMode::Static, DerivationMode::Sha512);
        println!("Outer circuit (static inner, SHA512) built successfully");
        println!("Circuit size: {} gates", outer.data.common.degree());
    }
    
    #[test]
    fn test_build_outer_circuit_with_static_inner_poseidon() {
        let inner = build_inner_circuit(SignatureMode::Static);
        let outer = build_outer_circuit(&inner.data.common, SignatureMode::Static, DerivationMode::Poseidon);
        println!("Outer circuit (static inner, Poseidon) built successfully");
        println!("Circuit size: {} gates", outer.data.common.degree());
    }
    
    #[test]
    fn test_build_outer_circuit_with_dynamic_inner_sha512() {
        let inner = build_inner_circuit(SignatureMode::Dynamic);
        let outer = build_outer_circuit(&inner.data.common, SignatureMode::Dynamic, DerivationMode::Sha512);
        println!("Outer circuit (dynamic inner, SHA512) built successfully");
        println!("Circuit size: {} gates", outer.data.common.degree());
    }
    
    #[test]
    fn test_build_outer_circuit_with_dynamic_inner_poseidon() {
        let inner = build_inner_circuit(SignatureMode::Dynamic);
        let outer = build_outer_circuit(&inner.data.common, SignatureMode::Dynamic, DerivationMode::Poseidon);
        println!("Outer circuit (dynamic inner, Poseidon) built successfully");
        println!("Circuit size: {} gates", outer.data.common.degree());
    }
}