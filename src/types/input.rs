//! Input data structures and configuration types for the zk-recursive proof system.
//!
//! This module defines the data structures used for:
//! - EUDI credential data (P-256 keys, signatures)
//! - Blockchain wallet data (secp256k1 keys)
//! - BIP32 key derivation parameters
//! - Circuit configuration modes (static/dynamic signatures, SHA512/Poseidon)

use serde::{Deserialize, Serialize};

/// Elliptic curve point representation (x, y coordinates as hex strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub x: String,
    pub y: String,
}

/// ECDSA signature representation (r, s values as hex strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: String,
    pub s: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureMode {
    Static,   // pk_issuer is static  
    Dynamic,  // pk_issuer is dynamic
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DerivationMode {
    Sha512,   // BIP32 key derivation with HMAC-SHA512
    Poseidon, // BIP32 key derivation with Poseidon hash
}

/// Circuit configuration for signature verification mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    pub signature_mode: SignatureMode,
}

/// Complete input data for the zk-recursive proof system.
/// Contains all necessary data for C1-C5 circuit computations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullInput {
    // C1+C2: EUDI Key Derivation (P256)
    pub pk_c: Point,
    pub sk_c: String,
    
    // C3: Signature Verification (P256)  
    pub pk_issuer: Point,  // Always present, validated against static values in Static mode
    pub msg: String,
    pub signature: Signature,
    
    // C4: Secp256k1 Key Derivation 
    pub sk_0: String,
    pub pk_0: Point,
    
    // C5: Key Derivation - Mode-dependent fields
    pub cc_0: String,
    pub derivation_index: u32,
    pub pk_i: Point,
    
    // SHA512-specific: Chain code output (optional for Poseidon mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc_i: Option<String>,
}
