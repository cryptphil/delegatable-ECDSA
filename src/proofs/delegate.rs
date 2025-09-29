use crate::cred::credential::SignedECDSACredential;
use crate::proofs::ecdsa::{fill_ecdsa_witness, make_ecdsa_circuit};
use crate::proofs::hash::{fill_sha256_circuit_witness, make_sha256_circuit};
use crate::proofs::scalar_conversion::{fill_digest2scalar_witness, make_digest2scalar_circuit};
use crate::utils::parsing::find_field_bit_indices;
use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_sha256::circuit::array_to_bits;
use std::time::Instant;

// TODO: potentially also split up in a build circuit function with all the targets and then a dedicated prove function.
pub fn init_delegation<F, Cfg, const D: usize>(
    cred: &SignedECDSACredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) -> Result<(ProofWithPublicInputs<F, Cfg, D>, VerifierCircuitData<F, Cfg, D>)>
where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Prove knowledge of a valid ECDSA signature.
    let ecdsa_circuit = make_ecdsa_circuit::<F, Cfg, D>(&mut builder);
    fill_ecdsa_witness::<F, Cfg, D>(&ecdsa_circuit, &mut pw, cred, iss_pk)?;

    // Prove that the credential hash as bytes converts to the credential hash as scalar.
    let cred_data_digest = cred.credential.hash_digest()?;
    let b2c_circuit = make_digest2scalar_circuit(&mut builder);
    fill_digest2scalar_witness(&b2c_circuit, &mut pw, &cred_data_digest, &cred.cred_hash)?;

    // Prove knowledge of the preimage of the credential hash while selectively revealing the
    // hashed public key.
    let cred_data_bits_vec = array_to_bits(&cred.credential.to_bytes()?);
    let cred_data_bits = cred_data_bits_vec.as_slice();
    let cred_digest_bits_vec = array_to_bits(&cred_data_digest);
    let cred_digest_bits = cred_digest_bits_vec.as_slice();
    let cred_json = cred.credential.to_json()?;


    // Prove knowledge of the sha256 preimage while revealing the credential public key.
    let (rev_idx, rev_num_bytes) = find_field_bit_indices(&cred_json, "cred_pk_sec1_compressed")?;
    let hash_circuit = make_sha256_circuit::<F, D>(&mut builder, cred_data_bits.len(), rev_idx, rev_num_bytes);
    fill_sha256_circuit_witness::<F, Cfg, D>(&hash_circuit, &mut pw, cred_data_bits, cred_digest_bits)?;
    // TODO: Convert the revealed public key bytes to some curve scalar or just in a format we want to work with later (hex is also fine I guess).

    // Now somehow register the level L=0 as public input.
    let level = builder.add_virtual_public_input();
    // Enforce L = 0
    builder.assert_zero(level);

    let build_start = Instant::now();
    let data = builder.build::<Cfg>();
    println!("Init delegation circuit generation time: {:?}", build_start.elapsed());
    let prove_start = Instant::now();
    let proof = data.prove(pw)?;
    println!("Init delegation proof generation time: {:?}", prove_start.elapsed());

    Ok((proof.clone(), data.verifier_data()))
}

#[allow(dead_code)]
pub fn prove_delegation_step<F, C, const D: usize>(
    verifier_data: &VerifierCircuitData<F, C, D>,
    inner_proof:   &ProofWithPublicInputs<F, C, D>,
    cred: &SignedECDSACredential,
) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Build one recursion layer
    let mut builder = CircuitBuilder::<F, D>::new(
        CircuitConfig::standard_recursion_zk_config()
    );

    // First check inner proof
    let proof_t = builder.add_virtual_proof_with_pis(&verifier_data.common);
    builder.register_public_inputs(&proof_t.public_inputs);

    let constants_sigmas_cap_t =
        builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);
    let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    let verifier_circuit_t = VerifierCircuitTarget {
        constants_sigmas_cap: constants_sigmas_cap_t,
        circuit_digest:       circuit_digest_t,
    };

    // TODO: Verify the proof for the (expected?) previous level L, which must be part of the public inputs.

    builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_t, inner_proof)?;

    // TODO: Now we add new constraints including that the new level L = prev_L + 1.

    let data = builder.build::<C>();

    let rec_start = Instant::now();
    let proof_recursive = data.prove(pw)?;
    println!("Recursive proof generation time (layer {}): {:?}", cred.credential.delegation_level, rec_start.elapsed());

    // Optional local verification of the newly created layer
    data.verify(proof_recursive.clone())?;
    println!("Recursive proof (layer {}) passed!", cred.credential.delegation_level);

    // Recurse to add remaining layers
    Ok((verifier_data.clone(), inner_proof.clone()))
}
