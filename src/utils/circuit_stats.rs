//! Circuit statistics and performance monitoring utilities

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::circuit_data::CommonCircuitData;
use std::collections::HashMap;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

fn extract_gate_base_type(gate_id: &str) -> String {
    if let Some(pos) = gate_id.find(" {") {
        gate_id[..pos].to_string()
    } else if let Some(pos) = gate_id.find('(') {
        gate_id[..pos].to_string()
    } else if let Some(pos) = gate_id.find('<') {
        gate_id[..pos].to_string()
    } else {
        gate_id.to_string()
    }
}

pub fn print_circuit_stats(name: &str, cd: &CommonCircuitData<F, D>) {
    println!("\n{name} Circuit Summary");
    println!("{}", "=".repeat(40));

    let mut gate_stats = HashMap::<String, (usize, usize)>::new(); // (selector_cols, max_constraints)
    let idx = &cd.selectors_info.selector_indices;

    // Note: We can only access gate types and selector indices from CommonCircuitData.
    // Actual gate instance counts would require access to the selector polynomial evaluations
    // which are not available in CommonCircuitData. So we show gate types and their
    // theoretical maximum constraint contribution.
    
    for (gate_idx, gate_ref) in cd.gates.iter().enumerate() {
        let gate = &gate_ref.0;
        let base_type = extract_gate_base_type(&gate.id());
        let constraints_per_instance = gate.num_constraints();
        
        // Number of selector columns for this gate type
        let selector_cols = if gate_idx + 1 < idx.len() {
            idx[gate_idx + 1] - idx[gate_idx]
        } else {
            cd.selectors_info.num_selectors() - idx[gate_idx]
        };

        if constraints_per_instance > 0 {
            gate_stats
                .entry(base_type)
                .and_modify(|e| {
                    e.0 += selector_cols;
                    e.1 = e.1.max(constraints_per_instance);
                })
                .or_insert((selector_cols, constraints_per_instance));
        }
    }

    let total_gate_types = gate_stats.len();
    let total_selector_cols: usize = gate_stats.values().map(|(cols, _)| cols).sum();
    let max_constraints_per_row: usize = gate_stats.values().map(|(_, constraints)| constraints).sum();

    // Summary block
    println!("Circuit Rows (degree):     {}", cd.degree());
    println!("Public Inputs:             {}", cd.num_public_inputs);
    println!("Constants:                 {}", cd.num_constants);
    println!("Gate Types:                {}", total_gate_types);
    println!("Selector Columns:          {}", total_selector_cols);
    println!("Max Constraints/Row:       {}", max_constraints_per_row);
    println!();

    // Gate breakdown - sorted by constraints per instance
    println!("Gate Types (sorted by constraints per instance):");
    let mut sorted_gates: Vec<_> = gate_stats.into_iter().collect();
    sorted_gates.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    println!("{:<25} {:>8} {:>15}", "Gate", "Selectors", "Constraints/Inst");
    for (gate, (selector_cols, constraints_per_inst)) in &sorted_gates {
        println!("{:<25} {:>8} {:>15}", gate, selector_cols, constraints_per_inst);
    }

    println!();
}
