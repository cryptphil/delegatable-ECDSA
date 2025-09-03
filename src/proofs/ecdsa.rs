use std::time::Instant;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::hash::hash_types::RichField;
use plonky2::field::extension::Extendable;
use plonky2::plonk::config::GenericConfig;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};
use plonky2_ecdsa::curve::curve_types::{Curve, CurveScalar};
use plonky2_ecdsa::gadgets::ecdsa::{verify_secp256k1_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget};
use plonky2::field::types::Sample;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use anyhow::Result;
use crate::cred::generate::IssuedEcdsaCredential;


#[allow(dead_code)]
/// Create a proof of knowledge of an ECDSA signature over secp256k1.
pub fn make_ecdsa_proof<F, C, const D: usize>(
    cred: &IssuedEcdsaCredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    type Curve = Secp256K1;

    let config = CircuitConfig::standard_ecc_config();
    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Message = credential hash (Secp256K1Scalar)
    let msg_target = builder.constant_nonnative(cred.cred_hash);

    // Public key
    let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(iss_pk.0));

    // Signature (r, s)
    let r_target = builder.constant_nonnative(cred.signature.r);
    let s_target = builder.constant_nonnative(cred.signature.s);
    let sig_target = ECDSASignatureTarget { r: r_target, s: s_target };

    // Verify inside circuit
    let build_start = Instant::now();
    verify_secp256k1_message_circuit(&mut builder, msg_target, sig_target, pk_target);
    let data = builder.build::<C>();
    println!("Circuit generation time: {:?}", build_start.elapsed());

    let prove_start = Instant::now();
    let proof = data.prove(pw)?;
    println!("Proof generation time: {:?}", prove_start.elapsed());
    data.verify(proof.clone())?;
    Ok((data.verifier_data(), proof))
}
