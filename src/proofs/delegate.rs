use crate::cred::credential::CredentialData;
use crate::proofs::scalar_conversion::build_sha256_to_scalar_circuit;
use crate::utils::parsing::set_nonnative_target;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;

#[allow(dead_code)]
pub fn gen_delegation_proof<F, C, const D: usize>(
    base_vcd:   &VerifierCircuitData<F, C, D>,
    base_proof: &ProofWithPublicInputs<F, C, D>,

    // private inputs
    cred_data: &CredentialData,
    cred_sk: &ECDSASecretKey<Secp256K1>,
    cred_pk: &ECDSAPublicKey<Secp256K1>,             // optional to constrain; kept private here
) -> anyhow::Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    use plonky2::iop::target::BoolTarget;
    use plonky2::plonk::circuit_data::VerifierCircuitTarget;
    use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
    use plonky2_sha256::circuit::{array_to_bits, make_circuits as sha_make_circuits};

    const LIMBS_PER_COORD: usize = 4; // Goldilocks nonnative limb split for secp256k1 scalar coords
    const LIMBS_PER_POINT: usize = LIMBS_PER_COORD * 2;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

    // A) Verify the inner/base proof (do NOT register its PIs)
    let inner_t = builder.add_virtual_proof_with_pis(&base_vcd.common);
    let cap_t  = builder.constant_merkle_cap(&base_vcd.verifier_only.constants_sigmas_cap);
    let dig_t  = builder.constant_hash(base_vcd.verifier_only.circuit_digest);
    let vct    = VerifierCircuitTarget { constants_sigmas_cap: cap_t, circuit_digest: dig_t };
    builder.verify_proof::<C>(&inner_t, &vct, &base_vcd.common);

    // B) Allocate OUTER public inputs with EXACT base layout,
    //    and CONNECT them to the corresponding inner proof PIs.
    // [ issuer_pk.x limbs | issuer_pk.y limbs | prev_pk.x limbs | prev_pk.y limbs | delegation_level  | cred_hash limbs (4) ]

    let inner_pis = &inner_t.public_inputs;
    let mut pi = 0usize;

    // 1) issuer_pk (x,y)
    let issuer_pk_pi_x: Vec<_> = (0..LIMBS_PER_COORD).map(|_| builder.add_virtual_public_input()).collect();
    for (i, t) in issuer_pk_pi_x.iter().enumerate() { builder.connect(*t, inner_pis[pi + i]); }
    pi += LIMBS_PER_COORD;
    let issuer_pk_pi_y: Vec<_> = (0..LIMBS_PER_COORD).map(|_| builder.add_virtual_public_input()).collect();
    for (i, t) in issuer_pk_pi_y.iter().enumerate() { builder.connect(*t, inner_pis[pi + i]); }
    pi += LIMBS_PER_COORD;

    // 2) prev_pk (x,y)
    let prev_pk_pi_x: Vec<_> = (0..LIMBS_PER_COORD).map(|_| builder.add_virtual_public_input()).collect();
    for (i, t) in prev_pk_pi_x.iter().enumerate() { builder.connect(*t, inner_pis[pi + i]); }
    pi += LIMBS_PER_COORD;
    let prev_pk_pi_y: Vec<_> = (0..LIMBS_PER_COORD).map(|_| builder.add_virtual_public_input()).collect();
    for (i, t) in prev_pk_pi_y.iter().enumerate() { builder.connect(*t, inner_pis[pi + i]); }
    pi += LIMBS_PER_COORD;

    // 3) delegation_level (public) and enforce L_cur = L_prev + 1
    let l_cur_pi = builder.add_virtual_public_input();
    let l_prev_pi = inner_pis[pi];
    let one = builder.one();
    let l_prev_plus_one = builder.add(l_prev_pi, one);
    builder.connect(l_cur_pi, l_prev_plus_one);
    pi += 1;

    // 4) cred_hash limbs (public) — mirror from inner PIs
    let cred_hash_pi_limbs: Vec<_> = (0..4).map(|_| builder.add_virtual_public_input()).collect();
    for (i, t) in cred_hash_pi_limbs.iter().enumerate() { builder.connect(*t, inner_pis[pi + i]); }
    pi += 4;

    debug_assert_eq!(pi, LIMBS_PER_POINT + LIMBS_PER_POINT + 1 + 4);

    // C) PRIVATE: SHA256(cred_data) inside circuit and bind to public cred_hash limbs

    // SHA gadget over private message bits
    let cred_json = cred_data.to_json_bytes()?;
    let msg_bits_host = array_to_bits(&cred_json);
    let sha = sha_make_circuits(&mut builder, msg_bits_host.len() as u64);

    // Pack 256 digest bits -> Secp256K1Scalar using your helper
    let digest_bool_targets: Vec<BoolTarget> = sha.digest.iter().map(|b| BoolTarget::new_unsafe(b.target)).collect();
    let digest_scalar_t: NonNativeTarget<Secp256K1Scalar> =
        build_sha256_to_scalar_circuit::<F, D>(&mut builder, &digest_bool_targets);

    // Connect digest limbs to the public cred_hash limbs (which are already connected to inner PIs)
    for i in 0..4 {
        builder.connect(digest_scalar_t.value.limbs[i].0, cred_hash_pi_limbs[i]);
    }

    // D) PRIVATE: presence of cred_sk and (optionally) cred_pk
    let cred_sk_t: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
    let _cred_pk_t = builder.add_virtual_affine_point_target();
    // Optional key correctness:
    // let calc_pk = builder.curve_mul_base_secp256k1(&cred_sk_t);
    // builder.connect_affine_points(calc_pk, _cred_pk_t);

    // E) Build and witness
    let data = builder.build::<C>();
    let mut pw = PartialWitness::<F>::new();

    // Inner proof witness
    pw.set_proof_with_pis_target(&inner_t, base_proof)?;

    // Private witnesses
    set_nonnative_target(&mut pw, &cred_sk_t, cred_sk.0)?;
    // If enabling key check:
    // pw.set_biguint_target(&_cred_pk_t.x.value, &cred_pk.0.x.to_canonical_biguint())?;
    // pw.set_biguint_target(&_cred_pk_t.y.value, &cred_pk.0.y.to_canonical_biguint())?;

    // SHA message bits
    for (i, bit) in msg_bits_host.iter().enumerate() {
        pw.set_bool_target(sha.message[i], *bit)?;
    }

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok((data.verifier_data(), proof))
}
