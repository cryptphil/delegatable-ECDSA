pub mod circuits;
pub mod types;
pub mod utils;
pub mod commands;

pub use circuits::{
    inner::{build_inner_circuit, InnerCircuit, InnerCircuitTargets},
    outer::{build_outer_circuit, OuterCircuit, OuterCircuitTargets},
};
pub use types::input::{FullInput, SignatureMode, CircuitConfig};