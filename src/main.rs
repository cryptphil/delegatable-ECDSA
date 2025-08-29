use std::{fs, path::Path};
use clap::Parser;
use anyhow::Result;
use env_logger::Env;

use zk_recursive::utils::circuit_stats::print_circuit_stats;
use zk_recursive::types::input::{SignatureMode, DerivationMode};

/// Command-line arguments for the zk-recursive proof generator
#[derive(Parser)]
#[command(name = "zk-recursive")]
#[command(about = "Generate recursive ZK-SNARK proofs")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
    
    #[arg(short, long, default_value = "build", help = "Output directory for artifacts")]
    output_dir: String,
}

/// Command structure with inner or outer proof generation commands
#[derive(Parser)]
enum Commands {
    /// Build inner circuit (C1-C4) and generate proof
    Inner {
        #[arg(short, long, help = "Input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Signature verification mode: static or dynamic")]
        sig_mode: String,
    },
    /// Build outer circuit with recursive verification and BIP32 key derivation
    Outer {
        #[arg(short, long, help = "Input JSON file with proof data")]
        input: String,
        #[arg(long, default_value = "dynamic", help = "Inner signature verification mode: static or dynamic")]
        inner_sig_mode: String,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    let args = Args::parse();
    use std::time::Instant;
    
    println!("=== ZK-RECURSIVE PLONKY2 PROOF SYSTEM ===");
    let total_start = Instant::now();
    
    let build_dir = Path::new(&args.output_dir);
    if !build_dir.exists() {
        fs::create_dir_all(build_dir).expect("Failed to create output directory");
    }
    
    match args.command {
        Some(Commands::Inner { input, sig_mode }) => {
            use zk_recursive::circuits::inner::build_inner_circuit;
            
            let signature_mode = match sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid signature mode: {}. Use 'static' or 'dynamic'", sig_mode);
                    std::process::exit(1);
                }
            };
            
            println!("\nBuilding Inner Circuit (C1-C4) with {} signature verification...", sig_mode);
            let inner_start = Instant::now();
            let inner = build_inner_circuit(signature_mode);
            let inner_total = inner_start.elapsed();
            println!("Inner circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner", &inner.data.common);
            
            println!("\n=== GENERATING INNER PROOF ===");
            use zk_recursive::commands::inner::generate_inner_proof;
            generate_inner_proof(&inner, &input, &build_dir)?;
        },
        Some(Commands::Outer { input, inner_sig_mode }) => {
            use zk_recursive::circuits::{inner::build_inner_circuit, outer::build_outer_circuit};
            
            let signature_mode = match inner_sig_mode.as_str() {
                "static" => SignatureMode::Static,
                "dynamic" => SignatureMode::Dynamic,
                _ => {
                    eprintln!("Invalid inner signature mode: {}. Use 'static' or 'dynamic'", inner_sig_mode);
                    std::process::exit(1);
                }
            };

            println!("\nBuilding Recursive Circuits with {} inner signature verification and {:?} derivation mode...", inner_sig_mode, DerivationMode::Poseidon);
            let inner_start = Instant::now();
            let inner = build_inner_circuit(signature_mode.clone());
            let inner_total = inner_start.elapsed();
            println!("Inner circuit build time: {:?}", inner_total);
            print_circuit_stats("Inner", &inner.data.common);
            
            let outer_start = Instant::now();
            let outer = build_outer_circuit(&inner.data.common, signature_mode, DerivationMode::Poseidon);
            let outer_total = outer_start.elapsed();
            println!("Outer circuit build time: {:?}", outer_total);
            print_circuit_stats("Outer", &outer.data.common);

            println!("\n=== GENERATING RECURSIVE PROOF ===");
            use zk_recursive::commands::outer::generate_outer_proof;
            generate_outer_proof(&inner, &outer, &input, &build_dir)?;
        },
        None => {
            println!("\nNo command specified. Available commands:");
            println!("  cargo run --release --bin zk-recursive -- inner --input inputs/input.json --sig-mode dynamic");
            println!("  cargo run --release --bin zk-recursive -- inner --input inputs/input.json --sig-mode static");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/input.json --inner-sig-mode dynamic");
            println!("  cargo run --release --bin zk-recursive -- outer --input inputs/input.json --inner-sig-mode static");
        }
    }
    
    println!("\nTotal execution time: {:?}", total_start.elapsed());
    println!("Artifacts saved to: {}", build_dir.display());
    println!("=== EXECUTION COMPLETE ===");
    
    Ok(())
}