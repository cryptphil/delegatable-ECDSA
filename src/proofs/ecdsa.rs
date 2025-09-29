use crate::cred::credential::SignedECDSACredential;
#[cfg(test)]
use crate::cred::credential::{generate_issuer_keypair, issue_fixed_dummy_credential};
use crate::utils::parsing::set_nonnative_target;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::PrimeField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
use plonky2_ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2_ecdsa::gadgets::ecdsa::{verify_secp256k1_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget};
use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use std::time::Instant;

#[allow(dead_code)]
pub struct ECDSACircuit<F: RichField + Extendable<D>, Cfg: GenericConfig<D, F = F>, const D: usize> {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: ECDSACircuitTargets<Secp256K1, Secp256K1Scalar>,
}

#[allow(dead_code)]
pub struct ECDSACircuitTargets<C: Curve, P: PrimeField> {
    pub issuer_pk: AffinePointTarget<C>,
    pub msg: NonNativeTarget<P>,
    pub sig: ECDSASignatureTarget<C>,
}

/// Add the ECDSA verification constraints to the circuit builder and return the targets.
/// Registers the issuer public key as public inputs (16 limbs).
pub fn make_ecdsa_circuit<F, Cfg, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ECDSACircuitTargets<Secp256K1, Secp256K1Scalar>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let msg_target = builder.add_virtual_nonnative_target();
    let r_target = builder.add_virtual_nonnative_target();
    let s_target = builder.add_virtual_nonnative_target();
    let pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
    let sig_target = ECDSASignatureTarget { r: r_target, s: s_target };

    // Register the issuer public key as public input.
    register_pk_as_pi::<F, Cfg, D>(builder, &pk_target);

    verify_secp256k1_message_circuit(builder, msg_target.clone(), sig_target.clone(), pk_target.clone());

    ECDSACircuitTargets {
        issuer_pk: pk_target.0,
        msg: msg_target,
        sig: sig_target,
    }
}

/// Fill the witness for the ECDSA circuit with the given ECDSA credential and issuer public key.
pub fn fill_ecdsa_witness<F, Cfg, const D: usize>(
    targets: &ECDSACircuitTargets<Secp256K1, Secp256K1Scalar>,
    pw: &mut PartialWitness<F>,
    cred: &SignedECDSACredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<()>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    // Fill witness with concrete values
    set_nonnative_target(pw, &targets.msg, cred.cred_hash)?;
    set_nonnative_target(pw, &targets.sig.r, cred.signature.r)?;
    set_nonnative_target(pw, &targets.sig.s, cred.signature.s)?;
    pw.set_biguint_target(&targets.issuer_pk.x.value, &iss_pk.0.x.to_canonical_biguint())?;
    pw.set_biguint_target(&targets.issuer_pk.y.value, &iss_pk.0.y.to_canonical_biguint())?;

    Ok(())
}

pub(crate) fn register_pk_as_pi<F, Cfg, const D: usize>(
    builder: &mut CircuitBuilder<impl RichField + Extendable<D>, D>,
    pk_target: &ECDSAPublicKeyTarget<Secp256K1>,
) where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let limbs_iter = pk_target.0.x.value.limbs.iter().chain(pk_target.0.y.value.limbs.iter());
    for limb in limbs_iter {
        builder.register_public_input(limb.0);
    }
}

#[test]
pub fn test_ecdsa_proof() -> Result<()> {
    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;
    type F = <Cfg as GenericConfig<D>>::F;

    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    let issuer = generate_issuer_keypair();
    let cred = issue_fixed_dummy_credential(&issuer.sk)?;

    let targets = make_ecdsa_circuit::<F, Cfg, D>(&mut builder);
    let build_start = Instant::now();
    let data = builder.build::<Cfg>();
    println!("ECDSA circuit generation time: {:?}", build_start.elapsed());

    fill_ecdsa_witness::<F, Cfg, D>(&targets, &mut pw, &cred, &issuer.pk)?;

    let prove_start = Instant::now();
    let proof = data.prove(pw)?;
    println!("ECDSA proof generation time: {:?}", prove_start.elapsed());

    data.verifier_data().verify(proof)
}



