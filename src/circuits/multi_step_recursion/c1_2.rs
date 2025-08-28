use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the C1_2 circuit (EUDI wallet key derivation + credential public key check).
pub struct C1_2CircuitTargets {
    pub pk_c: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
}

/// C1_2 circuit that implements C1 (EUDI wallet key derivation) + C2 (Credential public key check).
pub struct C1_2Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C1_2CircuitTargets,
}

/// Build the C1_2 circuit implementing:
/// - C1: pk_c = KeyDer(sk_c) - EUDI wallet key derivation over P256
/// - C2: pk_c === pk_c_calc - Public key equality check (pk_c extracted from EUDI credential)
pub fn build_c1_2_circuit() -> C1_2Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: EUDI public key (pk_c)
    let pk_c = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_c.x.value.limbs.iter().chain(pk_c.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: EUDI wallet secret key (P256)
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c_calc =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // === C2: Credential Public Key Check (pk_c === pk_c_calc) ===
    // Ensure the derived public key matches the public input
    builder.connect_affine_point(&pk_c_calc, &pk_c);

    let data = builder.build::<Cfg>();
    let targets = C1_2CircuitTargets { pk_c, sk_c };

    C1_2Circuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_c1_2_circuit() {
        let circuit = build_c1_2_circuit();
        println!("C1_2 circuit built successfully");
        println!("Circuit size: {} gates", circuit.data.common.degree());
    }
}