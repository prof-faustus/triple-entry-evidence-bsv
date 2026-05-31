// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! `tea-bsv-simstudy` binary: thin CLI over the library entry point.

#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use tee_simstudy::{run, to_json, SimStudyInputs, SEED};

#[derive(Parser)]
#[command(
    name = "tea-bsv-simstudy",
    about = "Synthetic-population study for triple-entry-evidence-bsv"
)]
struct Cli {
    /// Number of invoice notes to generate. Payments = floor(0.95 * M).
    #[arg(short = 'm', long, default_value_t = 200)]
    m: u32,
    /// Number of records to verify via Layer A inclusion proofs.
    #[arg(long, default_value_t = 64)]
    inclusion_sample: u32,
    /// Number of records to query via Layer B selective disclosure.
    #[arg(long, default_value_t = 64)]
    selective_sample: u32,
    /// Optional path to write the deterministic vector JSON.
    #[arg(long)]
    vector_out: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let inputs = SimStudyInputs {
        m_invoices: cli.m,
        inclusion_sample: cli.inclusion_sample,
        selective_sample: cli.selective_sample,
    };
    let v = run(inputs);

    println!("=== triple-entry-evidence-bsv simstudy ===");
    println!("seed = {SEED}");
    println!(
        "invoices M = {}, payments N = {}",
        v.m_invoices, v.n_payments
    );
    println!(
        "  Layer A inclusion: {}/{} verified",
        v.inclusion_detected, v.inclusion_sample
    );
    println!(
        "  Layer B selective:  {}/{} verified (k = {})",
        v.selective_detected, v.selective_sample, v.predetermined_level_k
    );
    for row in &v.faults {
        println!(
            "  fault.{}: injected={} detected={} missed={}",
            row.class, row.injected, row.detected, row.missed
        );
    }
    println!(
        "  origin_falsehood: injected=1 detected=0 (NOT DETECTED BY DESIGN — system boundary)"
    );

    if let Some(p) = cli.vector_out {
        std::fs::write(&p, to_json(&v)).expect("write");
        println!("wrote vector: {}", p.display());
    }
}
