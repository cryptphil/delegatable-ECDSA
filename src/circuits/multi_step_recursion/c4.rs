use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the C4 circuit (Secp256k1 Key Derivation + C3 recursive verification).
pub struct C4CircuitTargets {
    // Recursive verification targets
    pub c3_proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub c3_vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    
    pub pk_0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk_0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
}

/// C4 circuit that implements C4 (Secp256k1 Key Derivation) + recursive verification of C3.
pub struct C4Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C4CircuitTargets,
}

/// Build the C4 circuit implementing:
/// - Recursive verification of C3 proof
/// - C4: pk_0 = KeyDer(sk_0) - Blockchain wallet key derivation over secp256k1
pub fn build_c4_circuit(c3_common: &CommonCircuitData<F, D>) -> C4Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the C3 circuit and verify it recursively
    let c3_proof = builder.add_virtual_proof_with_pis(c3_common);
    let c3_vd = builder.add_virtual_verifier_data(c3_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&c3_proof, &c3_vd, c3_common);

    // === Public Input: Secp256k1 Public Key ===
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk_0.x.value.limbs.iter().chain(pk_0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // === Private Input: Secp256k1 Secret Key ===
    let sk_0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // === C4: Blockchain Wallet Key Derivation (pk_0 = KeyDer(sk_0)) ===
    // Derive public key from secret key using secp256k1 base point multiplication
    let pk_0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk_0,
    );
    
    // Ensure the derived public key matches the public input
    builder.connect_affine_point(&pk_0_calc, &pk_0);

    let data = builder.build::<Cfg>();
    let targets = C4CircuitTargets {
        c3_proof,
        c3_vd,
        pk_0,
        sk_0,
    };

    C4Circuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::multi_step_recursion::c1_2::build_c1_2_circuit;
    use crate::circuits::multi_step_recursion::c3::build_c3_circuit;
    use crate::types::input::SignatureMode;
    
    #[test]
    fn test_build_c4_circuit_with_static_c3() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Static);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        println!("C4 circuit (with static C3) built successfully");
        println!("Circuit size: {} gates", c4_circuit.data.common.degree());
    }
    
    #[test]
    fn test_build_c4_circuit_with_dynamic_c3() {
        let c1_2_circuit = build_c1_2_circuit();
        let c3_circuit = build_c3_circuit(&c1_2_circuit.data.common, SignatureMode::Dynamic);
        let c4_circuit = build_c4_circuit(&c3_circuit.data.common);
        println!("C4 circuit (with dynamic C3) built successfully");
        println!("Circuit size: {} gates", c4_circuit.data.common.degree());
    }
}