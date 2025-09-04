//! Parsing and conversion utilities for cryptographic data.

use anyhow::{Result, bail};
use plonky2::field::extension::Extendable;
use plonky2::field::types::{PrimeField, PrimeField64};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Convert hex string (with or without 0x prefix) to BigUint
pub fn hex_to_bigint(hex_str: &str) -> num_bigint::BigUint {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    num_bigint::BigUint::parse_bytes(hex_clean.as_bytes(), 16)
        .expect("Invalid hex string")
}

/// Convert hex string (with or without 0x prefix) to fixed-size big-endian byte array.
/// Pads with leading zeros if too short, truncates if too long.
pub fn hex_to_fixed_be_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_clean).expect("Invalid hex string");
    
    let mut out = [0u8; N];
    let src = if bytes.len() > N {
        &bytes[bytes.len() - N..]
    } else {
        &bytes[..]
    };
    out[N - src.len()..].copy_from_slice(src);
    out
}

/// Helper to set a nonnative field element as a circuit target value
pub fn set_nonnative_target<F, FF: PrimeField, const D: usize>(
    pw: &mut PartialWitness<F>,
    target: &plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<FF>,
    value: FF,
) -> Result<()>
where
    F: PrimeField64 + Extendable<D>,
    FF: PrimeField,
{
    pw.set_biguint_target(&target.value, &value.to_canonical_biguint())?;
    Ok(())
}

/// Writes bytes as bits (per byte: MSB→LSB) in BoolTargets.
/// Expects: targets.len() == bytes.len() * 8
pub fn set_bytes_as_bits_be<FF>(
    pw: &mut PartialWitness<FF>,
    targets: &[BoolTarget],
    bytes: &[u8],
) -> Result<()>
where
    FF: PrimeField64,
{
    let need = bytes.len() * 8;
    if targets.len() != need {
        bail!("expected {} bit targets, got {}", need, targets.len());
    }
    let mut k = 0;
    for &b in bytes {
        // per byte big-endian (Bit 7 → Bit 0)
        for i in (0..8).rev() {
            let bit = ((b >> i) & 1) == 1;
            pw.set_bool_target(targets[k], bit)?;
            k += 1;
        }
    }
    Ok(())
}

/// Writes a u32 as 32 bits big-endian (MSB→LSB) in BoolTargets.
/// Enforces non-hardened (MSB=0) for BIP32.
pub fn set_u32_be_bits_non_hardened<FF>(
    pw: &mut PartialWitness<FF>,
    targets: &[BoolTarget], // len == 32
    index: u32,
) -> Result<()>
where
    FF: PrimeField64,
{
    if targets.len() != 32 {
        bail!("derivation_index targets must be exactly 32 bits");
    }
    if (index & 0x8000_0000) != 0 {
        bail!("hardened index not allowed (MSB=1). Use index < 2^31.");
    }
    for (i, &tgt) in targets.iter().enumerate() {
        let bit = ((index >> (31 - i)) & 1) == 1;
        pw.set_bool_target(tgt, bit)?;
    }
    Ok(())
}
