use crate::cred::credential::SignedECDSACredential;
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
use std::time::Instant;


pub fn init_delegation<F, Cfg, const D: usize>(
    cred: &SignedECDSACredential,
    iss_pk: &ECDSAPublicKey<Secp256K1>,
) where
    F: RichField + Extendable<D>,
    Cfg: GenericConfig<D, F=F>,
{
    // let mut config = CircuitConfig::standard_ecc_config();
    // config.zero_knowledge = true;
    // let mut builder = CircuitBuilder::<F, D>::new(config);
    // let mut pw = PartialWitness::new();

    // TODO:
    // We now need to prove that the ECDSA signature is valid on the given hash w.r.t. iss pk
    // then we need to prove the conversion of a hash bytes to hash scalar as verified in the ecdsa circuit.
    // Given the hash as bytes, we prove knowledge of the preimage of the hash and reveal the user's public key (in the end, we will also reveal some other attributes).
    // Also, we provide an public proof input that corresponds to the level and set L=0.
    // The final proof should now verify with public inputs: (pk_iss, pk_user, L=0)

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

    builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_t, inner_proof)?;

    // Then prove current cred
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
