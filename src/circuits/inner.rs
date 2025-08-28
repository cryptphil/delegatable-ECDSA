//! Inner circuit implementation for the unified EUDI-Web3 proof system.
//!
//! This module implements the inner circuit (C1-C4) that proves:
//! - C1: EUDI wallet key derivation over P-256
//! - C2: Credential public key equality check
//! - C3: EUDI credential signature verification (static/dynamic issuer)
//! - C4: Blockchain wallet key derivation over secp256k1

use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::ecdsa::{
    verify_p256_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecdsa::add_static_pk_ecdsa_verify_constraints;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2::field::types::Field;

use crate::types::input::SignatureMode;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

// Fixed issuer public key values
const STATIC_PK_ISSUER_X: &str = "66432692286261411630769223098970693805397596870633670159153355502222145619968";
const STATIC_PK_ISSUER_Y: &str = "63182586149833488067701290985084360701345487374231728189741684364091950142361";

/// Targets for the inner circuit.
/// Contains fields for all components C1-C4 with pk_issuer always present.
#[allow(dead_code)]
pub struct InnerCircuitTargets {
    // C1+C2: EUDI Key Derivation (P256)
    pub pk_c: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    
    // C3: Signature Verification (P256) - pk_issuer always present, validated in static mode
    pub pk_issuer: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
    
    // C4: Secp256k1 Key Derivation
    pub pk_0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk_0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
}

/// Inner circuit that implements C1-C4 with configurable signature verification mode.
#[allow(dead_code)]
pub struct InnerCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: InnerCircuitTargets,
    pub signature_mode: SignatureMode,
}

/// Build the inner circuit.
/// - C1: pk_c = KeyDer(sk_c) - EUDI wallet key derivation over P256
/// - C2: pk_c === pk_c_calc - Public key equality check  
/// - C3: SigVerify(pk_I, msg, sig) - Credential signature verification over P256 (static/dynamic)
/// - C4: pk_0 = KeyDer(sk_0) - Blockchain wallet key derivation over secp256k1
pub fn build_inner_circuit(signature_mode: SignatureMode) -> InnerCircuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: secp256k1 blockchain wallet public key (pk_0)
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk_0.x.value.limbs.iter().chain(pk_0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Public input: issuer public key (always present, validated in static mode)
    let pk_issuer = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_issuer.x.value.limbs.iter().chain(pk_issuer.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private inputs for P256 operations
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // Private inputs: credential public key (extracted from c.cnf.jwk)
    let pk_c = builder.add_virtual_affine_point_target::<P256>();
    
    // Private input: EUDI wallet secret key (P256)
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // Private input: secp256k1 blockchain wallet secret key
    let sk_0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c_calc =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // === C2: Credential Public Key Check (pk_c === pk_c_calc) ===
    // Ensure the derived public key matches the key stored in the credential
    builder.connect_affine_point(&pk_c_calc, &pk_c);

    // === C3: Credential Signature Verification ===
    // Verify that the credential was validly signed by a trusted issuer
    match signature_mode {
        SignatureMode::Dynamic => {
            // Dynamic mode: pk_issuer from public input is used directly
            let pk_target = ECDSAPublicKeyTarget(pk_issuer.clone());
            verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);
        }
        SignatureMode::Static => {
            // Static mode: use hardcoded issuer public key with lookup table optimization
            add_static_pk_ecdsa_verify_constraints(&mut builder, msg.clone(), signature.clone());
            
            // Additionally validate that pk_issuer matches the fixed static values
            let expected_x = BigUint::from_str_radix(STATIC_PK_ISSUER_X, 10).unwrap();
            let expected_y = BigUint::from_str_radix(STATIC_PK_ISSUER_Y, 10).unwrap();
            
            // Add constraints to ensure pk_issuer matches expected values  
            // Use the p256_base field for the coordinates
            use plonky2_ecdsa::field::p256_base::P256Base;
            let expected_x_target = builder.constant_nonnative(P256Base::from_noncanonical_biguint(expected_x));
            let expected_y_target = builder.constant_nonnative(P256Base::from_noncanonical_biguint(expected_y));
            
            builder.connect_nonnative(&pk_issuer.x, &expected_x_target);
            builder.connect_nonnative(&pk_issuer.y, &expected_y_target);
        }
    }

    // === C4: Blockchain Wallet Key Derivation (pk_0 = KeyDer(sk_0)) ===
    // Derive public key from secret key using secp256k1 base point multiplication
    let pk_0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk_0,
    );
    builder.connect_affine_point(&pk_0_calc, &pk_0);

    let data = builder.build::<Cfg>();
    let targets = InnerCircuitTargets {
        pk_c,
        sk_c,
        pk_issuer,
        msg,
        sig: signature,
        pk_0,
        sk_0,
    };

    InnerCircuit {
        data,
        targets,
        signature_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_inner_circuit_dynamic() {
        let inner = build_inner_circuit(SignatureMode::Dynamic);
        println!("Inner circuit (dynamic mode) built successfully");
        println!("Circuit size: {} gates", inner.data.common.degree());
    }
    
    #[test]
    fn test_build_inner_circuit_static() {
        let inner = build_inner_circuit(SignatureMode::Static);
        println!("Inner circuit (static mode) built successfully");
        println!("Circuit size: {} gates", inner.data.common.degree());
    }
}