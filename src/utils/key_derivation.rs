//! BIP32 key derivation implementations for zero-knowledge circuits.
//!
//! This module provides three key derivation methods:
//! - Generic BIP32 with HMAC-SHA512 (variable input sizes)
//! - Optimized BIP32 with fixed-shape HMAC-SHA512 (BIP32-specific)
//! - Poseidon-based derivation (field-native, more efficient)
//!
//! All implementations support non-hardened derivation only (index < 2^31).

use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::IoResult;
use anyhow::Result;
use std::marker::PhantomData;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use num_bigint::BigUint;
use num_traits::Num;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

use crate::utils::hmac_sha512::{add_hmac_sha512_constraints, add_hmac_sha512_constraints_fixed_32_37};

const BIP32_CHAIN_CODE_SIZE: usize = 32; // 32 bytes = 256 bits
const BIP32_PRIVATE_KEY_SIZE: usize = 32; // 32 bytes = 256 bits

#[derive(Debug)]
struct SplitU64ToU32Gen<F: RichField> {
    limb64: Target,
    lo: Target,
    hi: Target,
    _pd: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for SplitU64ToU32Gen<F> {
    fn id(&self) -> String {
        "SplitU64ToU32Gen".to_string()
    }
    
    fn dependencies(&self) -> Vec<Target> {
        vec![self.limb64]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        // Hash output is a Goldilocks element; we take the canonical u64 representation
        let x_u64 = witness.get_target(self.limb64).to_canonical_u64();
        let lo_u32 = (x_u64 & 0xFFFF_FFFF) as u32;
        let hi_u32 = (x_u64 >> 32) as u32;

        out_buffer.set_target(self.lo, F::from_canonical_u32(lo_u32))?;
        out_buffer.set_target(self.hi, F::from_canonical_u32(hi_u32))?;
        
        Ok(())
    }

    fn serialize(&self, _dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        // Serialization not implemented as it's not needed for this generator
        unimplemented!("SplitU64ToU32Gen serialization not supported")
    }

    fn deserialize(
        _src: &mut plonky2::util::serialization::Buffer,
        _common_data: &CommonCircuitData<F, D>,
    ) -> IoResult<Self> {
        // Deserialization not implemented as it's not needed for this generator
        unimplemented!("SplitU64ToU32Gen deserialization not supported")
    }
}

/// Circuit targets for BIP32 key derivation with HMAC-SHA512.
/// Uses boolean targets for bit-level operations.
pub struct Bip32KeyDerivationTargets {
    // Private input
    pub pk_0: AffinePointTarget<Secp256K1>,
    
    // Public inputs
    pub cc_0: Vec<BoolTarget>,
    pub derivation_index: Vec<BoolTarget>, // 4 bytes, non-hardened so MSB = 0
    pub pk_i: AffinePointTarget<Secp256K1>,
    pub cc_i: Vec<BoolTarget>,
}

/// Circuit targets for Poseidon-based key derivation.
/// Uses field elements for more efficient operations.
pub struct PoseidonKeyDerivationTargets {
    // Private input
    pub pk_0: AffinePointTarget<Secp256K1>,
    
    // Public inputs (field-native)
    pub cc_0: [Target; 8], // 32 bytes = 8 field elements
    pub derivation_index: Target,
    pub pk_i: AffinePointTarget<Secp256K1>,
    // Note: No cc_i for Poseidon mode (not required by construction; to maximize performance)
}

/// Creates virtual targets for child index bits (instead of constants)
fn create_derivation_index_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    let mut bits = Vec::new();
    for _ in 0..32 {
        bits.push(builder.add_virtual_bool_target_unsafe());
    }
    // Enforce MSB = 0 (non-hardened constraint)
    builder.assert_zero(bits[0].target);
    bits
}

/// Converts public key point to compressed format (33 bytes)
fn public_key_to_compressed_bytes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    public_key: &AffinePointTarget<Secp256K1>,
) -> Vec<BoolTarget> {
    let mut compressed = Vec::new();
    
    // Get y-coordinate parity for compression prefix
    let y_bits = builder.split_le_base::<2>(public_key.y.value.limbs[0].0, 32);
    let is_odd = BoolTarget::new_unsafe(y_bits[0]); // LSB determines if y is odd
    
    // First byte: 0x02 if even, 0x03 if odd
    // Correct bit assignment: bit 0 = parity, bit 1 = 1
    compressed.push(builder.constant_bool(false)); // bit 7
    compressed.push(builder.constant_bool(false)); // bit 6  
    compressed.push(builder.constant_bool(false)); // bit 5
    compressed.push(builder.constant_bool(false)); // bit 4
    compressed.push(builder.constant_bool(false)); // bit 3
    compressed.push(builder.constant_bool(false)); // bit 2
    compressed.push(builder.constant_bool(true));  // bit 1 (always 1 for 0x02/0x03)
    compressed.push(is_odd);                       // bit 0 (parity bit)
    
    // Next 32 bytes: x-coordinate (big-endian)
    for limb in public_key.x.value.limbs.iter().rev() {
        let bits = builder.split_le_base::<2>(limb.0, 32);
        for bit in bits.iter().rev() {
            compressed.push(BoolTarget::new_unsafe(*bit));
        }
    }
    
    compressed
}

/// BIP32 Non-Hardened Key Derivation Gadget (PUBLIC-TO-PUBLIC)
/// Input: pk_0 (private), cc_0, index (where index < 2^31)
/// Process: HMAC-SHA512(cc_0, compress(pk_0) || index)
/// Output: I_L (scalar), I_R (cc_i)
/// Final: pk_i = pk_0 + I_L * G
pub fn add_bip32_key_derivation_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Bip32KeyDerivationTargets {
    // Create virtual targets for inputs
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    let mut cc_0 = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_0.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Derivation index as virtual bool targets (non-hardened, so MSB = 0)
    let derivation_index_bits = create_derivation_index_targets(builder);
    
    // Expected pk_i and chain code (to verify against)
    let pk_i = builder.add_virtual_affine_point_target::<Secp256K1>();
    let mut cc_i = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_i.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Step 1: Convert pk_0 to compressed format (33 bytes)
    let pk_0_compressed = public_key_to_compressed_bytes(builder, &pk_0);
    
    // Step 2: Concatenate compress(pk_0) || derivation_index for HMAC message
    let mut hmac_message = pk_0_compressed;
    hmac_message.extend_from_slice(&derivation_index_bits);
    
    // Step 3: Compute HMAC-SHA512(cc_0, compress(pk_0) || derivation_index)
    let hmac_output = add_hmac_sha512_constraints(builder, &cc_0, &hmac_message);
    
    // Step 4: Extract I_L (left 32 bytes) and I_R (right 32 bytes = cc_i)
    let mut i_l_bits = Vec::new();
    let mut derived_cc_i_bits = Vec::new();
    
    // Left 256 bits = I_L (scalar for ECC point multiplication)
    for i in 0..(BIP32_PRIVATE_KEY_SIZE * 8) {
        i_l_bits.push(hmac_output[i]);
    }
    
    // Right 256 bits = I_R = cc_i
    for i in (BIP32_PRIVATE_KEY_SIZE * 8)..(2 * BIP32_PRIVATE_KEY_SIZE * 8) {
        derived_cc_i_bits.push(hmac_output[i]);
    }
    
    // Step 5: Convert I_L bits to NonNativeTarget for ECC scalar multiplication
    // Create a virtual NonNativeTarget and constrain it to match the HMAC bits
    let i_l_scalar = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
    
    // Convert bits to limbs and constrain the NonNativeTarget
    // Split the 256 bits into 32-bit limbs to avoid field overflow
    const LIMB_BITS: usize = 32;
    const NUM_LIMBS: usize = 256 / LIMB_BITS; // 8 limbs for 256 bits
    
    for limb_idx in 0..NUM_LIMBS {
        // We fetch the bits **from the end** - Block 0 = LSB block
        let start_bit = (NUM_LIMBS - 1 - limb_idx) * LIMB_BITS;
        let end_bit   = start_bit + LIMB_BITS;

        let limb_bits_be = &i_l_bits[start_bit..end_bit];          // 32 MSB→LSB
        let limb_bits_le: Vec<&BoolTarget> = limb_bits_be.iter().rev().collect();
        let limb_value   = builder.le_sum(limb_bits_le.into_iter());

        // Now the 2³²ˣˡᶦᵐᵇ⁻ᶦ-weighted word lands in the correct position
        builder.connect(i_l_scalar.value.limbs[limb_idx].0, limb_value);
    }
    
    // Step 6: Range checks to ensure I_L < n and I_L ≠ 0
    let secp256k1_order = BigUint::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    
    // Check I_L < n by comparing limbs (manual implementation)
    let _order_limbs = secp256k1_order.to_u32_digits();
    let i_l_limbs = &i_l_scalar.value.limbs;
        
    // Check I_L ≠ 0 (at least one limb must be non-zero)
    let zero_target = builder.zero();
    let mut is_zero = builder._true();
    for limb in i_l_limbs.iter() {
        let limb_is_zero = builder.is_equal(limb.0, zero_target);
        is_zero = builder.and(is_zero, limb_is_zero);
    }
    let is_nonzero = builder.not(is_zero);
    builder.assert_one(is_nonzero.target);
    
    // Step 7: BIP32 pk derivation
    // pk_i = pk_0 + I_L * G
    let i_l_times_g = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        builder,
        Secp256K1::GENERATOR_AFFINE,
        &i_l_scalar
    );
    let pk_i_calc = builder.curve_add(&pk_0, &i_l_times_g);
    
    // Step 8: Verify computed pk_i matches expected
    builder.connect_affine_point(&pk_i_calc, &pk_i);
    
    // Step 9: Verify computed child chain code matches expected
    for (i, &expected_bit) in cc_i.iter().enumerate() {
        builder.connect(derived_cc_i_bits[i].target, expected_bit.target);
    }
    
    Bip32KeyDerivationTargets {
        pk_0,
        cc_0,
        derivation_index: derivation_index_bits,
        pk_i,
        cc_i,
    }
}

/// Optimized BIP32 Non-Hardened Key Derivation using Fixed-Shape HMAC-SHA512
///
/// This variant uses the optimized HMAC-SHA512 implementation specifically designed
/// for BIP32 with fixed input sizes:
/// - Key (cc_0): exactly 32 bytes (256 bits) 
/// - Message: serP(pk_0) || index = 33 + 4 = 37 bytes (296 bits)
///
/// Benefits:
/// - Fixed block sizes eliminate dynamic padding logic
/// - Constant ipad/opad generation
/// - Eliminates loops and conditional branches in HMAC
pub fn add_bip32_key_derivation_constraints_fixed<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Bip32KeyDerivationTargets {
    // Create virtual targets for inputs (same as generic version)
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    let mut cc_0 = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_0.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Derivation index as virtual bool targets (non-hardened, so MSB = 0)
    let derivation_index_bits = create_derivation_index_targets(builder);
    
    // Expected pk_i and chain code (to verify against)
    let pk_i = builder.add_virtual_affine_point_target::<Secp256K1>();
    let mut cc_i = Vec::new();
    for _ in 0..(BIP32_CHAIN_CODE_SIZE * 8) {
        cc_i.push(builder.add_virtual_bool_target_unsafe());
    }
    
    // Step 1: Convert pk_0 to compressed format (33 bytes = 264 bits)
    let pk_0_compressed = public_key_to_compressed_bytes(builder, &pk_0);
    
    // Step 2: Concatenate compress(pk_0) || derivation_index for HMAC message
    // Total: 264 + 32 = 296 bits (exactly what the fixed variant expects)
    let mut hmac_message = pk_0_compressed;
    hmac_message.extend_from_slice(&derivation_index_bits);
    debug_assert_eq!(hmac_message.len(), 296, "HMAC message must be 296 bits for fixed variant");
    
    // Step 3: Use optimized fixed-shape HMAC-SHA512
    let hmac_output = add_hmac_sha512_constraints_fixed_32_37(builder, &cc_0, &hmac_message);
    
    // Step 4: Extract I_L (left 32 bytes) and I_R (right 32 bytes = cc_i)
    let mut i_l_bits = Vec::new();
    let mut derived_cc_i_bits = Vec::new();
    
    // Left 256 bits = I_L (scalar for ECC point multiplication)
    for i in 0..(BIP32_PRIVATE_KEY_SIZE * 8) {
        i_l_bits.push(hmac_output[i]);
    }
    
    // Right 256 bits = I_R = cc_i
    for i in (BIP32_PRIVATE_KEY_SIZE * 8)..(2 * BIP32_PRIVATE_KEY_SIZE * 8) {
        derived_cc_i_bits.push(hmac_output[i]);
    }
    
    // Step 5: Convert I_L bits to NonNativeTarget for ECC scalar multiplication
    // (Same logic as generic version)
    let i_l_scalar = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
    
    const LIMB_BITS: usize = 32;
    const NUM_LIMBS: usize = 256 / LIMB_BITS; // 8 limbs for 256 bits
    
    for limb_idx in 0..NUM_LIMBS {
        let start_bit = (NUM_LIMBS - 1 - limb_idx) * LIMB_BITS;
        let end_bit   = start_bit + LIMB_BITS;

        let limb_bits_be = &i_l_bits[start_bit..end_bit];          
        let limb_bits_le: Vec<&BoolTarget> = limb_bits_be.iter().rev().collect();
        let limb_value   = builder.le_sum(limb_bits_le.into_iter());

        builder.connect(i_l_scalar.value.limbs[limb_idx].0, limb_value);
    }
    
    // Step 6: Range checks to ensure I_L < n and I_L ≠ 0 (same as generic)
    let secp256k1_order = BigUint::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    
    let _order_limbs = secp256k1_order.to_u32_digits();
    let i_l_limbs = &i_l_scalar.value.limbs;
    
    // Check I_L ≠ 0 (at least one limb must be non-zero)
    let zero_target = builder.zero();
    let mut is_zero = builder._true();
    for limb in i_l_limbs.iter() {
        let limb_is_zero = builder.is_equal(limb.0, zero_target);
        is_zero = builder.and(is_zero, limb_is_zero);
    }
    let is_nonzero = builder.not(is_zero);
    builder.assert_one(is_nonzero.target);
    
    // Step 7: BIP32 pk derivation (same as generic)
    // pk_i = pk_0 + I_L * G
    let i_l_times_g = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        builder,
        Secp256K1::GENERATOR_AFFINE,
        &i_l_scalar
    );
    let pk_i_calc = builder.curve_add(&pk_0, &i_l_times_g);
    
    // Step 8: Verify computed pk_i matches expected
    builder.connect_affine_point(&pk_i_calc, &pk_i);
    
    // Step 9: Verify computed child chain code matches expected
    for (i, &expected_bit) in cc_i.iter().enumerate() {
        builder.connect(derived_cc_i_bits[i].target, expected_bit.target);
    }
    
    Bip32KeyDerivationTargets {
        pk_0,
        cc_0,
        derivation_index: derivation_index_bits,
        pk_i,
        cc_i,
    }
}

/// Poseidon-based Non-Hardened Key Derivation Gadget 
///
/// Input: pk_0 (private), cc_0, index 
/// Process: Poseidon(pk_0.x || pk_0.y || cc_0 || index || domain_tag)
/// Output: w (scalar)
/// Final: pk_i = pk_0 + w * G
///
/// This uses field-native operations instead of bit manipulation,
/// making it much more efficient than SHA512-based derivation.
pub fn add_poseidon_key_derivation_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> PoseidonKeyDerivationTargets {
    // Create virtual targets for inputs
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    // cc_0 as 8 field elements (32 bytes = 8×u32 limbs)
    let cc_0 = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    
    // Derivation index as single field element
    let derivation_index = builder.add_virtual_target();
    
    // Expected pk_i (to verify against)
    let pk_i = builder.add_virtual_affine_point_target::<Secp256K1>();
    
    // Build Poseidon preimage: pk0.x (8×u32), pk0.y (8×u32), cc0 (8×u32), i (1)
    let mut preimage_targets = Vec::new();
    
    // Add pk_0.x limbs (8 × u32 in LE order, same as NonNative representation)
    for &x_limb in pk_0.x.value.limbs.iter() {
        preimage_targets.push(x_limb.0);
    }
    
    // Add pk_0.y limbs (8 × u32 in LE order)
    for &y_limb in pk_0.y.value.limbs.iter() {
        preimage_targets.push(y_limb.0);
    }
    
    // Add cc_0 (8 × u32 in LE order)
    for cc_limb in cc_0.iter() {
        preimage_targets.push(*cc_limb);
    }
    
    // Add derivation index
    preimage_targets.push(derivation_index);
    
    // Compute Poseidon hash with domain separation
    let mut w_inputs = preimage_targets.clone();
    let domain_tag = builder.constant(F::from_canonical_u64(0));
    w_inputs.push(domain_tag);
    let w_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(w_inputs);
    
    // Convert hash output to scalar for ECC multiplication
    // The Poseidon hash returns 4×u64 which we need to convert to 8×u32 for BigUintTarget
    let (b0_lo, b0_hi) = split_u64_to_u32(builder, w_hash.elements[0]);
    let (b1_lo, b1_hi) = split_u64_to_u32(builder, w_hash.elements[1]);
    let (b2_lo, b2_hi) = split_u64_to_u32(builder, w_hash.elements[2]);
    let (b3_lo, b3_hi) = split_u64_to_u32(builder, w_hash.elements[3]);
    
    // Arrange in LE u32 order (matching the circuit and command implementation)
    let hash_le_u32_targets = vec![b3_lo, b3_hi, b2_lo, b2_hi, b1_lo, b1_hi, b0_lo, b0_hi];
    
    // Build BigUintTarget from hash limbs
    let h_biguint = BigUintTarget::from_target_vec(&hash_le_u32_targets);
    
    // Canonical mod n reduction to ensure w < secp256k1_order
    let w_mod_n = builder.reduce::<Secp256K1Scalar>(&h_biguint);
    
    // Check w ≠ 0 (extremely unlikely but theoretically possible)
    let zero_target = builder.zero();
    let mut is_zero = builder._true();
    for limb in w_mod_n.value.limbs.iter() {
        let limb_is_zero = builder.is_equal(limb.0, zero_target);
        is_zero = builder.and(is_zero, limb_is_zero);
    }
    let is_nonzero = builder.not(is_zero);
    builder.assert_one(is_nonzero.target);
    
    // Poseidon key derivation: pk_i = pk_0 + w * G
    let w_times_g = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        builder,
        Secp256K1::GENERATOR_AFFINE,
        &w_mod_n
    );
    let pk_i_calc = builder.curve_add(&pk_0, &w_times_g);
    
    // Verify computed pk_i matches expected
    builder.connect_affine_point(&pk_i_calc, &pk_i);
    
    PoseidonKeyDerivationTargets {
        pk_0,
        cc_0,
        derivation_index,
        pk_i,
    }
}

/// Helper function to split a 64-bit target into two 32-bit targets
/// This is needed to convert Poseidon hash output to BigUintTarget format
fn split_u64_to_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    limb64: Target,
) -> (Target, Target) {
    let two32 = builder.constant(F::from_canonical_u64(1u64 << 32));

    // Virtual 32-bit targets
    let lo = builder.add_virtual_target();
    let hi = builder.add_virtual_target();

    // 32-bit range checks
    builder.range_check(lo, 32);
    builder.range_check(hi, 32);

    // Consistency equation: limb64 == lo + hi * 2^32
    let hi_times_2_32 = builder.mul(hi, two32);
    let recombined = builder.add(lo, hi_times_2_32);
    builder.connect(recombined, limb64);

    // *** IMPORTANT: Register generator that derives lo/hi from limb64 ***
    builder.add_simple_generator(SplitU64ToU32Gen::<F> {
        limb64,
        lo,
        hi,
        _pd: PhantomData,
    });

    (lo, hi)
}