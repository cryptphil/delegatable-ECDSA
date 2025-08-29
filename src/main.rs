use std::time::Instant;
use anyhow::Result;
use plonky2::{
    field::{secp256k1_scalar::Secp256K1Scalar, types::Sample},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_data::{VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::{
    curve::{
        curve_types::{Curve, CurveScalar},
        ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
    gadgets::{
        curve::CircuitBuilderCurve,
        ecdsa::{verify_secp256k1_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
        nonnative::CircuitBuilderNonNative,
    },
};

fn make_ecdsa_proof<F, C, const D: usize, U>(
) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    type Curve = Secp256K1;

    let config = CircuitConfig::standard_ecc_config();
    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let msg = Secp256K1Scalar::rand();
    let msg_target = builder.constant_nonnative(msg);


    let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

    let sig = sign_message(msg, sk);

    let ECDSASignature { r, s } = sig;
    let r_target = builder.constant_nonnative(r);
    let s_target = builder.constant_nonnative(s);
    let sig_target = ECDSASignatureTarget {
        r: r_target,
        s: s_target,
    };
    println!("{sig:?}");

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

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let (verifier_data, proof) = make_ecdsa_proof::<F, C, D, Secp256K1>()?;

    // Recursive proof
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let proof_t = builder.add_virtual_proof_with_pis(&verifier_data.common);
    builder.register_public_inputs(&proof_t.public_inputs); // Now has the same public inputs as the inner proof

    let constants_sigmas_cap_t =
        builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);

    let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    let verifier_circuit_t = VerifierCircuitTarget {
        constants_sigmas_cap: constants_sigmas_cap_t,
        circuit_digest: circuit_digest_t,
    };

    builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_t, &proof)?;
    let data = builder.build::<C>();

    let rec_proof_start = Instant::now();
    let proof_recursive = data.prove(pw)?;
    println!("Recursive proof generation time: {:?}", rec_proof_start.elapsed());

    data.verify(proof_recursive.clone())?;
    println!("Recursive proof passed!");
    println!("public inputs :{:?}", proof_recursive.public_inputs);


    Ok(())
}