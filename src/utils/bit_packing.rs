//! Packing utilities

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

const D: usize = 2;

/// Pack boolean targets into field elements for more efficient public input handling.
/// Each field element can hold up to 32 bits for Goldilocks field (safe limit).
pub fn pack_bool_targets_to_field_elements<F: RichField + Extendable<D>>(
    bits: &[BoolTarget],
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<Target> {
    bits.chunks(32) // Safe for Goldilocks field
        .map(|chunk| {
            builder.le_sum(chunk.iter().copied())
        })
        .collect()
}

/// Pack a `Vec<BoolTarget>` (256 bits) into 8 field elements.
pub fn pack_256_bits_to_field_elements<F: RichField + Extendable<D>>(
    bits: &Vec<BoolTarget>,
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<Target> {
    assert_eq!(bits.len(), 256, "Expected exactly 256 bits");
    
    bits.chunks(32) // 256 bits / 32 bits per field element = 8 field elements
        .map(|chunk| {
            builder.le_sum(chunk.iter().copied())
        })
        .collect()
}

/// Pack a `Vec<BoolTarget>` (32 bits) into 1 field element.
pub fn pack_32_bits_to_field_element<F: RichField + Extendable<D>>(
    bits: &Vec<BoolTarget>,
    builder: &mut CircuitBuilder<F, D>,
) -> Target {
    assert_eq!(bits.len(), 32, "Expected exactly 32 bits");
    
    builder.le_sum(bits.iter().copied())
}