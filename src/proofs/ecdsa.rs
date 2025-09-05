use crate::cred::generate::IssuedEcdsaCredential;
use crate::utils::parsing::set_nonnative_target;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::PrimeField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
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
    pub pk_issuer: AffinePointTarget<C>,
    pub msg: NonNativeTarget<P>,
    pub sig: ECDSASignatureTarget<C>,
}


pub fn build_ecdsa_circuit<F, Cfg, const D: usize>() -> ECDSACircuit<F, Cfg, D>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Allocate *targets* instead of constants
    let msg_target = builder.add_virtual_nonnative_target();
    let r_target = builder.add_virtual_nonnative_target();
    let s_target = builder.add_virtual_nonnative_target();
    let pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());

    let sig_target = ECDSASignatureTarget { r: r_target, s: s_target };

    verify_secp256k1_message_circuit(&mut builder, msg_target.clone(), sig_target.clone(), pk_target.clone());
    let data = builder.build::<Cfg>();

    let targets = ECDSACircuitTargets {
        pk_issuer: pk_target.0,
        msg: msg_target,
        sig: sig_target,
    };

    ECDSACircuit { data, targets }
}


pub fn prove_ecdsa<F, Cfg, const D: usize>(
    circuit: &ECDSACircuit<F, Cfg, D>,
    cred: &IssuedEcdsaCredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<ProofWithPublicInputs<F, Cfg, D>>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let mut pw = PartialWitness::new();

    // Fill witness with concrete values
    set_nonnative_target(&mut pw, &circuit.targets.msg, cred.cred_hash)?;
    set_nonnative_target(&mut pw, &circuit.targets.sig.r, cred.signature.r)?;
    set_nonnative_target(&mut pw, &circuit.targets.sig.s, cred.signature.s)?;
    pw.set_biguint_target(&circuit.targets.pk_issuer.x.value, &iss_pk.0.x.to_canonical_biguint())?;
    pw.set_biguint_target(&circuit.targets.pk_issuer.y.value, &iss_pk.0.y.to_canonical_biguint())?;

    // let mut timing = TimingTree::new("inner_proof", Level::Info);
    // let proof = prove(&circuit.data.prover_only, &circuit.data.common, pw, &mut timing);
    // proof
    circuit.data.prove(pw)
}


pub fn make_ecdsa_proof<F, Cfg, const D: usize>(
    cred: &IssuedEcdsaCredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<(VerifierCircuitData<F, Cfg, D>, ProofWithPublicInputs<F, Cfg, D>)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F = F>,
{
    let build_start = Instant::now();
    let circuit = build_ecdsa_circuit::<F, Cfg, D>();
    println!("ECDSA circuit generation time: {:?}", build_start.elapsed());
    let prove_start = Instant::now();
    let proof = prove_ecdsa(&circuit, cred, iss_pk)?;
    println!("ECDSA proof generation time: {:?}", prove_start.elapsed());
    circuit.data.verify(proof.clone())?;
    Ok((circuit.data.verifier_data(), proof))
}


// /// Create a proof of knowledge of an ECDSA signature over secp256k1.
// pub fn make_ecdsa_proof<F, C, const D: usize>(
//     cred: &IssuedEcdsaCredential,
//     iss_pk: &ECDSAPublicKey<Secp256K1>,
// ) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
// where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F>,
// {
//     type Curve = Secp256K1;
//
//     let config = CircuitConfig::standard_ecc_config();
//     let pw = PartialWitness::new();
//     let mut builder = CircuitBuilder::<F, D>::new(config);
//
//     // Message = credential hash (Secp256K1Scalar)
//     let msg_target = builder.constant_nonnative(cred.cred_hash);
//
//     // Public key
//     let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(iss_pk.0));
//
//     // Signature (r, s)
//     let r_target = builder.constant_nonnative(cred.signature.r);
//     let s_target = builder.constant_nonnative(cred.signature.s);
//     let sig_target = ECDSASignatureTarget { r: r_target, s: s_target };
//
//     // Verify inside circuit
//     let build_start = Instant::now();
//     verify_secp256k1_message_circuit(&mut builder, msg_target, sig_target, pk_target);
//     let data = builder.build::<C>();
//     println!("Circuit generation time: {:?}", build_start.elapsed());
//
//     let prove_start = Instant::now();
//     let proof = data.prove(pw)?;
//     println!("Proof generation time: {:?}", prove_start.elapsed());
//     data.verify(proof.clone())?;
//     Ok((data.verifier_data(), proof))
// }
