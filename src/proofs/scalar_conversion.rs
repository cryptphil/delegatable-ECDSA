use crate::utils::parsing::{byte_array_to_scalar, set_nonnative_target};
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use plonky2_sha256::circuit::array_to_bits;
use sha2::{Digest, Sha256};

pub struct Digest2ScalarTargets {
    pub digest_bits_targets: Vec<BoolTarget>,
    pub expected_scalar: NonNativeTarget<Secp256K1Scalar>,
}

/// Builds a circuit that packs a 32 Bytes digest into a `Secp256K1Scalar` as a nonnative target.
pub fn make_digest2scalar_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Digest2ScalarTargets {
    let digest_targets: Vec<BoolTarget> = (0..256)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();
    let expected_scalar: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();

    for limb_idx in 0..8 {
        let mut limb = builder.zero();
        for bit_in_limb in 0..32 {
            let bit = digest_targets[255 - (limb_idx * 32 + bit_in_limb)];

            let coeff = builder.constant(F::from_canonical_u64(1u64 << bit_in_limb));
            let contrib = builder.mul(bit.target, coeff);

            limb = builder.add(limb, contrib);
        }
        builder.connect(limb, expected_scalar.value.limbs[limb_idx].0);
    }

    Digest2ScalarTargets {
        digest_bits_targets: digest_targets,
        expected_scalar,
    }
}

pub fn fill_digest2scalar_witness<F, const D: usize>(
    circuit: &Digest2ScalarTargets,
    pw: &mut PartialWitness<F>,
    digest: &[u8; 32],
    scalar: &Secp256K1Scalar,
) -> Result<()>
where
    F: RichField + Extendable<D>,
{
    let digests_targets = &circuit.digest_bits_targets;
    let digest_bits_val = array_to_bits(digest);
    for (t, bit) in digests_targets.iter().zip(digest_bits_val.iter()) {
        pw.set_bool_target(*t, *bit)?;
    }

    set_nonnative_target(pw, &circuit.expected_scalar, *scalar)?;

    Ok(())
}

/// Build & prove a hash→scalar circuit for a given digest.
pub fn make_digest2scalar_proof<F, Cfg, const D: usize>(
    digest: &[u8; 32],
) -> Result<(VerifierCircuitData<F, Cfg, D>, ProofWithPublicInputs<F, Cfg, D>)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let scalar = byte_array_to_scalar(digest)?;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::new();

    let circuit = make_digest2scalar_circuit::<F, D>(&mut builder);

    let build_start = std::time::Instant::now();

    let data = builder.build::<Cfg>();
    println!("Hash→Scalar circuit generation time: {:?}", build_start.elapsed());

    fill_digest2scalar_witness::<F, D>(&circuit, &mut pw, digest, &scalar)?;

    let prove_start = std::time::Instant::now();
    let proof = data.prove(pw)?;
    println!("Hash→Scalar proof generation time: {:?}", prove_start.elapsed());

    Ok((data.verifier_data(), proof))
}

#[test]
fn test_digest_to_scalar_proof() -> Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let message = b"Hello, world!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest = hasher.finalize();
    let digest_arr: [u8; 32] = digest.into();

    let (vcd, proof) = make_digest2scalar_proof::<F, Cfg, D>(&digest_arr)?;

    vcd.verify(proof)?;

    Ok(())
}