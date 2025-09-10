use crate::utils::parsing::byte_array_to_scalar;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use plonky2_sha256::circuit::array_to_bits;
use sha2::{Digest, Sha256};

/// Build a circuit that converts 256 SHA256 digest bits into a Secp256K1ScalarTarget.
///
/// `digest_bits`: slice of 256 boolean targets (MSB first)
/// Returns: the scalar target
fn build_sha256_to_scalar_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    digest_bits: &[BoolTarget],
) -> NonNativeTarget<Secp256K1Scalar> {
    let scalar_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();

    // 3. Pack 256 digest bits -> 4 * 64-bit limbs
    let mut limb_targets = Vec::new();
    for limb_idx in 0..4 {
        let mut limb = builder.zero();
        for bit_in_limb in 0..64 {
            let bit_idx = limb_idx * 64 + bit_in_limb;
            let bit = digest_bits[bit_idx];
            let coeff = builder.constant(F::from_canonical_u64(1u64 << (63 - bit_in_limb)));
            let contrib = builder.mul(bit.target, coeff);

            limb = builder.add(limb, contrib);
        }
        limb_targets.push(limb);
        builder.connect(limb, scalar_target.value.limbs[limb_idx].0);
    }

    scalar_target
}


#[test]
fn test_scalar_conversion() -> anyhow::Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let message = b"Hello, world!";
    let digest = Sha256::digest(message); // 32 bytes
    let expected_scalar = byte_array_to_scalar(digest.as_slice())?;

    // Build the circuit
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

    // Add digest bits as BoolTargets
    let digest_bits: Vec<BoolTarget> = (0..256)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();

    let scalar_target = build_sha256_to_scalar_circuit::<F, D>(&mut builder, &digest_bits);

    // Now create constant targets for the expected limbs and connect them to the scalar's limbs.
    // This enforces scalar_target == expected scalar inside the circuit.
    for (i, &limb_val) in expected_scalar.0.iter().enumerate() {
        // create a field-constant target equal to the limb value
        let const_t = builder.constant(F::from_canonical_u64(limb_val));
        // connect the constant to the corresponding internal limb target of the nonnative scalar
        let eq = builder.is_equal(const_t, scalar_target.value.limbs[i].0);
        builder.assert_one(eq.target);
    }

    let data = builder.build::<Cfg>();
    let mut pw = PartialWitness::new();

    let digest_bits_val = array_to_bits(&digest);
    for (t, bit) in digest_bits.iter().zip(digest_bits_val.iter()) {
        pw.set_bool_target(*t, *bit)?;
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;

    Ok(())
}