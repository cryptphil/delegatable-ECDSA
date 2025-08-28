use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints_fixed, Bip32KeyDerivationTargets,
    add_poseidon_key_derivation_constraints, PoseidonKeyDerivationTargets,
};
use crate::types::input::DerivationMode;
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Key derivation targets (mode-dependent)
pub enum C5KeyDerivationTargets {
    Bip32(Bip32KeyDerivationTargets),
    Poseidon(PoseidonKeyDerivationTargets),
}

/// Targets for the C5 circuit (Key Derivation + C4 recursive verification).
pub struct C5CircuitTargets {
    // Recursive verification targets
    pub c4_proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub c4_vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    
    // Key Derivation targets (mode-dependent)
    pub key_derivation_targets: C5KeyDerivationTargets,
}

/// C5 circuit that implements C5 (BIP32 Key Derivation) + recursive verification of C4.
pub struct C5Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C5CircuitTargets,
    pub derivation_mode: DerivationMode,
}

/// Build the C5 circuit implementing:
/// - Recursive verification of C4 proof
/// - C5: BIP32 non-hardened key derivation: pk_i = KeyDer(pk_0, cc_0, i)
pub fn build_c5_circuit(
    c4_common: &CommonCircuitData<F, D>,
    derivation_mode: DerivationMode,
) -> C5Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the C4 circuit and verify it recursively
    let c4_proof = builder.add_virtual_proof_with_pis(c4_common);
    let c4_vd = builder.add_virtual_verifier_data(c4_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&c4_proof, &c4_vd, c4_common);

    // === pk_0 Consistency Check ===
    // Ensure the same pk_0 is used in both outer and inner circuits
    // This prevents malicious users from using different keys
    
    // Add pk_0 as private input to outer circuit
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    // Extract pk_0 from inner circuit's public inputs (first 8 field elements)
    // Inner circuit registers pk_0 as: x_limbs (4) + y_limbs (4) = 8 field elements total
    let c4_pk_0_x_limbs = [
        c4_proof.public_inputs[0],
        c4_proof.public_inputs[1], 
        c4_proof.public_inputs[2],
        c4_proof.public_inputs[3],
    ];
    let c4_pk_0_y_limbs = [
        c4_proof.public_inputs[4],
        c4_proof.public_inputs[5],
        c4_proof.public_inputs[6], 
        c4_proof.public_inputs[7],
    ];
    
    // Connect outer private pk_0 with inner public pk_0
    for (c5_limb, &c4_limb) in pk_0.x.value.limbs.iter().zip(c4_pk_0_x_limbs.iter()) {
        builder.connect(c5_limb.0, c4_limb);
    }
    for (c5_limb, &c4_limb) in pk_0.y.value.limbs.iter().zip(c4_pk_0_y_limbs.iter()) {
        builder.connect(c5_limb.0, c4_limb);
    }

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
            
            C5KeyDerivationTargets::Bip32(targets)
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
            
            // Note: No cc_i for Poseidon mode (no chain code output)
            
            C5KeyDerivationTargets::Poseidon(targets)
        }
    };

    let data = builder.build::<Cfg>();
    let targets = C5CircuitTargets {
        c4_proof,
        c4_vd,
        key_derivation_targets,
    };

    C5Circuit { data, targets, derivation_mode }
}

/// Build the C5 circuit with the specified derivation mode.
pub fn build_c5_circuit_optimized(c4_common: &CommonCircuitData<F, D>, derivation_mode: DerivationMode) -> C5Circuit {
    build_c5_circuit(c4_common, derivation_mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::multi_step_recursion::c1_2::build_c1_2_circuit;
    use crate::circuits::multi_step_recursion::c3::build_c3_circuit;
    use crate::circuits::multi_step_recursion::c4::build_c4_circuit;
    use crate::types::input::SignatureMode;
    
    #[test]
    fn test_build_c5_circuit_with_static_chain_sha512() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Static);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        let c5_circuit = build_c5_circuit_optimized(&c4_circuit.data.common, DerivationMode::Sha512);
        println!("C5 circuit (static chain, SHA512) built successfully");
        println!("Circuit size: {} gates", c5_circuit.data.common.degree());
    }
    
    #[test]
    fn test_build_c5_circuit_with_static_chain_poseidon() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Static);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        let c5_circuit = build_c5_circuit_optimized(&c4_circuit.data.common, DerivationMode::Poseidon);
        println!("C5 circuit (static chain, Poseidon) built successfully");
        println!("Circuit size: {} gates", c5_circuit.data.common.degree());
    }
    
    #[test]
    fn test_build_c5_circuit_with_dynamic_chain_sha512() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Dynamic);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        let c5_circuit = build_c5_circuit_optimized(&c4_circuit.data.common, DerivationMode::Sha512);
        println!("C5 circuit (dynamic chain, SHA512) built successfully");
        println!("Circuit size: {} gates", c5_circuit.data.common.degree());
    }
    
    #[test]
    fn test_build_c5_circuit_with_dynamic_chain_poseidon() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Dynamic);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        let c5_circuit = build_c5_circuit_optimized(&c4_circuit.data.common, DerivationMode::Poseidon);
        println!("C5 circuit (dynamic chain, Poseidon) built successfully");
        println!("Circuit size: {} gates", c5_circuit.data.common.degree());
    }
}