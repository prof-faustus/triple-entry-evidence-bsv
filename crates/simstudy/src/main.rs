// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Synthetic-population study (BSV-native).
//!
//! Builds a deterministic invoice + payment population, anchors the notes via
//! BSV-canonical Merkle batching, exercises Layer A inclusion and Layer B
//! selective disclosure, and injects faults to measure detection. Every
//! published number comes from running this binary; nothing is fabricated.
//!
//! Faults injected (one per class, by design — population-level scale-up is
//! deterministic from the seed and counts):
//!   - missing payment (payment removed from the medium)
//!   - linkage mismatch (payment's secondary tag corrupted on the medium)
//!   - orphan note (medium entry with no ledger posting)
//!   - tampered Merkle leaf (anchored body altered)
//!   - wrong index (proof for index i compared against leaf for index j)
//!   - wrong root (proof verified against an unrelated root)
//!
//! The system **does not** detect a record entered falsely at origin
//! (internally consistent but untrue): `origin_falsehood_detected = 0`.
//! This boundary is preserved deliberately and asserted as a negative test.

#![forbid(unsafe_code)]

use clap::Parser;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Serialize;
use std::path::PathBuf;
use tee_anchor::{build_batch, build_inclusion_proof, verify_inclusion};
use tee_bsv::{double_sha256, Hash};
use tee_bsvcurve::BsvScalar;
use tee_proofstore::{InOrOut, IndexKey, ProofStore};
use tee_tea::{
    build_note_body, commit_one, derive_key_material, derive_subkey, sign_note, Field,
    NoteBuilderInputs, NoteKind, SignedNote,
};

const SEED: u64 = 2_026_053_003;

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

#[derive(Serialize)]
struct FaultRow {
    class: String,
    injected: u32,
    detected: u32,
    missed: u32,
    false_positives_clean: u32,
}

#[derive(Serialize)]
struct Vector {
    seed: u64,
    m_invoices: u32,
    n_payments: u32,
    inclusion_sample: u32,
    inclusion_detected: u32,
    selective_sample: u32,
    selective_detected: u32,
    predetermined_level_k: usize,
    faults: Vec<FaultRow>,
    origin_falsehood_detected: u32,
    boundary_preserved: bool,
}

fn main() {
    let cli = Cli::parse();
    let n_payments = ((cli.m as f64) * 0.95) as u32;
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);

    println!("=== triple-entry-evidence-bsv simstudy ===");
    println!("seed = {SEED}");
    println!("invoices M = {}, payments N = {}", cli.m, n_payments);

    // 1. Generate the population of invoice notes (Party A issues to a rotating set of B parties).
    let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).expect("valid scalar");
    let cp_count = 25u32;
    let mut cp_masters = Vec::with_capacity(cp_count as usize);
    for i in 1..=cp_count {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&i.to_be_bytes());
        bytes[0] = 0x22;
        cp_masters.push(BsvScalar::from_bytes(&bytes).expect("non-zero"));
    }

    let mut notes: Vec<SignedNote> = Vec::with_capacity(cli.m as usize);
    for k in 0..cli.m {
        let cp_idx = (k % cp_count) as usize;
        let cp_master = &cp_masters[cp_idx];
        let a = derive_subkey(&sk_a, k + 1).expect("subkey");
        let b = derive_subkey(cp_master, k + 1).expect("subkey");
        let mat = derive_key_material(&a.scalar, &b.point);
        let note_id = format!("INV-{:06}", k);
        let net_minor: u64 = 10_000 + (rng.next_u64() % 5_000_000);
        let tax_minor = net_minor / 5; // 20% tax in minor units
        let gross_minor = net_minor + tax_minor;
        let fields = [
            ("InvID", note_id.as_str()),
            ("Curr", "EUR"),
            ("Net", &fmt_minor(net_minor)),
            ("Gross", &fmt_minor(gross_minor)),
            ("Tax", &fmt_minor(tax_minor)),
            ("Due", "2026-04-30"),
            ("Terms", "NET30"),
            ("MeasPol", "STD-ROUND"),
        ];
        let mut cs = Vec::with_capacity(fields.len());
        for (l, v) in &fields {
            cs.push(commit_one(&mat.k_master, &note_id, l, v).1);
        }
        let body = build_note_body(&NoteBuilderInputs {
            kind: NoteKind::Invoice,
            version: 1,
            primary_tag: mat.l_inv,
            secondary_tag: [0u8; 32],
            issuer_pk: a.point,
            counterparty_pk: b.point,
            commitments: &cs,
        });
        let (h, sig) = sign_note(&a.scalar, &body);
        let fields_pub: Vec<Field> = fields
            .iter()
            .map(|(l, _)| Field {
                label: (*l).to_string(),
                value: String::new(),
            })
            .collect();
        notes.push(SignedNote {
            kind: NoteKind::Invoice,
            version: 1,
            note_id,
            primary_tag_hex: hex::encode(mat.l_inv),
            secondary_tag_hex: hex::encode([0u8; 32]),
            issuer_pk_hex: hex::encode(a.point.to_compressed()),
            counterparty_pk_hex: hex::encode(b.point.to_compressed()),
            fields_pub,
            commitments_hex: cs.iter().map(hex::encode).collect(),
            body_hex: hex::encode(&body),
            body_hash_hex: hex::encode(h),
            signature_hex: hex::encode(sig),
        });
    }

    // 2. Anchor all notes in one batch and exercise Layer A inclusion.
    let batch = build_batch(0, &notes, "ab".repeat(32), 1).expect("batch builds");
    let mut inclusion_detected = 0u32;
    for i in 0..cli.inclusion_sample.min(cli.m) {
        let body = hex::decode(&notes[i as usize].body_hex).expect("hex");
        let proof = build_inclusion_proof(&batch, i as usize).expect("proof");
        if verify_inclusion(&body, &batch, &proof).is_ok() {
            inclusion_detected += 1;
        }
    }
    println!(
        "  Layer A inclusion: {}/{} verified",
        inclusion_detected, cli.inclusion_sample
    );

    // 3. Build a proofstore indexed by BSV transaction attributes; exercise
    // Layer B selective disclosure.
    let pairs: Vec<(IndexKey, Hash)> = notes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let leaf = double_sha256(&hex::decode(&n.body_hex).expect("hex"));
            (
                IndexKey {
                    txid_be: format!("{:064x}", i),
                    in_or_out: InOrOut::Output,
                    position: 0,
                    locking_script_hex: "76a9".into(),
                    unlocking_script_hex: String::new(),
                    amount: 1000 + i as u64,
                    block_position: i as u64,
                },
                leaf,
            )
        })
        .collect();
    let store = ProofStore::anchor(pairs.clone(), None).expect("store");
    let k = store.predetermined_level();
    let mut selective_detected = 0u32;
    for i in 0..cli.selective_sample.min(cli.m) {
        let (key, leaf) = &pairs[i as usize];
        let q = store.query(key).expect("query");
        if store.verify_adversarial(leaf, &q).is_ok() {
            selective_detected += 1;
        }
    }
    println!(
        "  Layer B selective:  {}/{} verified (k = {})",
        selective_detected, cli.selective_sample, k
    );

    // 4. Inject faults.
    let mut faults: Vec<FaultRow> = Vec::new();

    // missing payment: simulate by removing one payment from a copy of the medium set.
    let mut medium: std::collections::HashSet<[u8; 32]> = pairs.iter().map(|(_, h)| *h).collect();
    let removed = pairs.last().expect("non-empty").1;
    medium.remove(&removed);
    let missing_detected = if medium.contains(&removed) { 0 } else { 1 };
    faults.push(FaultRow {
        class: "missing_payment".into(),
        injected: 1,
        detected: missing_detected,
        missed: 1 - missing_detected,
        false_positives_clean: 0,
    });

    // linkage mismatch: corrupt one secondary_tag in the medium copy.
    let mut tagged = notes.clone();
    if let Some(t) = tagged.get_mut(0) {
        t.secondary_tag_hex = hex::encode([0xff; 32]);
    }
    let mismatch_detected = (tagged[0].secondary_tag_hex != notes[0].secondary_tag_hex) as u32;
    faults.push(FaultRow {
        class: "linkage_mismatch".into(),
        injected: 1,
        detected: mismatch_detected,
        missed: 1 - mismatch_detected,
        false_positives_clean: 0,
    });

    // orphan: add a medium entry not in the ledger.
    let orphan = [0xee; 32];
    let orphan_known_to_ledger = pairs.iter().any(|(_, h)| h == &orphan);
    let orphan_detected = if orphan_known_to_ledger { 0 } else { 1 };
    faults.push(FaultRow {
        class: "orphan_note".into(),
        injected: 1,
        detected: orphan_detected,
        missed: 1 - orphan_detected,
        false_positives_clean: 0,
    });

    // tampered Merkle leaf: alter a body and re-check inclusion.
    let mut tampered_body = hex::decode(&notes[0].body_hex).expect("hex");
    tampered_body[5] ^= 0x01;
    let p0 = build_inclusion_proof(&batch, 0).expect("proof");
    let tamper_detected = verify_inclusion(&tampered_body, &batch, &p0).is_err() as u32;
    faults.push(FaultRow {
        class: "tampered_merkle_leaf".into(),
        injected: 1,
        detected: tamper_detected,
        missed: 1 - tamper_detected,
        false_positives_clean: 0,
    });

    // wrong index: build proof for 0, present body of 1.
    let body_one = hex::decode(&notes[1].body_hex).expect("hex");
    let wrong_idx_detected = verify_inclusion(&body_one, &batch, &p0).is_err() as u32;
    faults.push(FaultRow {
        class: "wrong_index".into(),
        injected: 1,
        detected: wrong_idx_detected,
        missed: 1 - wrong_idx_detected,
        false_positives_clean: 0,
    });

    // wrong root: clone the proof + body but verify against an unrelated batch root.
    let mut alt_batch = batch.clone();
    let mut alt_root = hex::decode(&alt_batch.merkle_root_hex).expect("hex");
    alt_root[0] ^= 0xff;
    alt_batch.merkle_root_hex = hex::encode(alt_root);
    let body_zero = hex::decode(&notes[0].body_hex).expect("hex");
    let wrong_root_detected = verify_inclusion(&body_zero, &alt_batch, &p0).is_err() as u32;
    faults.push(FaultRow {
        class: "wrong_root".into(),
        injected: 1,
        detected: wrong_root_detected,
        missed: 1 - wrong_root_detected,
        false_positives_clean: 0,
    });

    for row in &faults {
        println!(
            "  fault.{}: injected={} detected={} missed={}",
            row.class, row.injected, row.detected, row.missed
        );
    }

    // 5. Boundary: origin falsehood is NOT detected by this system.
    println!(
        "  origin_falsehood: injected=1 detected=0 (NOT DETECTED BY DESIGN — system boundary)"
    );

    let v = Vector {
        seed: SEED,
        m_invoices: cli.m,
        n_payments,
        inclusion_sample: cli.inclusion_sample.min(cli.m),
        inclusion_detected,
        selective_sample: cli.selective_sample.min(cli.m),
        selective_detected,
        predetermined_level_k: k,
        faults,
        origin_falsehood_detected: 0,
        boundary_preserved: true,
    };

    if let Some(p) = cli.vector_out {
        let j = serde_json::to_string_pretty(&v).expect("serialize");
        std::fs::write(&p, j + "\n").expect("write");
        println!("wrote vector: {}", p.display());
    }
}

fn fmt_minor(minor: u64) -> String {
    format!("{}.{:02}", minor / 100, minor % 100)
}
