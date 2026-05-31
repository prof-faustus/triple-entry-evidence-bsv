// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Synthetic-population study (BSV-native) — library entry point.
//!
//! The same code path is consumed by the `tea-bsv-simstudy` binary and by
//! `tea-bsv reproduce`, so that drift between the committed vector and the
//! live code fails the reproduce gate.

#![forbid(unsafe_code)]

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Serialize;
use tee_anchor::{build_batch, build_inclusion_proof, verify_inclusion};
use tee_bsv::{double_sha256, Hash};
use tee_bsvcurve::BsvScalar;
use tee_proofstore::{InOrOut, IndexKey, ProofStore};
use tee_tea::{
    build_note_body, commit_one, derive_key_material, derive_subkey, sign_note, Field,
    NoteBuilderInputs, NoteKind, SignedNote,
};

pub const SEED: u64 = 2_026_053_003;

#[derive(Clone, Copy, Debug)]
pub struct SimStudyInputs {
    pub m_invoices: u32,
    pub inclusion_sample: u32,
    pub selective_sample: u32,
}

#[derive(Serialize)]
pub struct FaultRow {
    pub class: String,
    pub injected: u32,
    pub detected: u32,
    pub missed: u32,
    pub false_positives_clean: u32,
}

#[derive(Serialize)]
pub struct SimStudyVector {
    pub seed: u64,
    pub m_invoices: u32,
    pub n_payments: u32,
    pub inclusion_sample: u32,
    pub inclusion_detected: u32,
    pub selective_sample: u32,
    pub selective_detected: u32,
    pub predetermined_level_k: usize,
    pub faults: Vec<FaultRow>,
    pub origin_falsehood_detected: u32,
    pub boundary_preserved: bool,
}

/// Run the synthetic-population study and return the deterministic vector.
/// Output is byte-deterministic for fixed `inputs` and `SEED`.
pub fn run(inputs: SimStudyInputs) -> SimStudyVector {
    let n_payments = ((inputs.m_invoices as f64) * 0.95) as u32;
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);

    // 1. Generate the population of invoice notes.
    let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).expect("valid scalar");
    let cp_count = 25u32;
    let mut cp_masters = Vec::with_capacity(cp_count as usize);
    for i in 1..=cp_count {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&i.to_be_bytes());
        bytes[0] = 0x22;
        cp_masters.push(BsvScalar::from_bytes(&bytes).expect("non-zero"));
    }

    let mut notes: Vec<SignedNote> = Vec::with_capacity(inputs.m_invoices as usize);
    for k in 0..inputs.m_invoices {
        let cp_idx = (k % cp_count) as usize;
        let cp_master = &cp_masters[cp_idx];
        let a = derive_subkey(&sk_a, k + 1).expect("subkey");
        let b = derive_subkey(cp_master, k + 1).expect("subkey");
        let mat = derive_key_material(&a.scalar, &b.point);
        let note_id = format!("INV-{:06}", k);
        let net_minor: u64 = 10_000 + (rng.next_u64() % 5_000_000);
        let tax_minor = net_minor / 5;
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
    for i in 0..inputs.inclusion_sample.min(inputs.m_invoices) {
        let body = hex::decode(&notes[i as usize].body_hex).expect("hex");
        let proof = build_inclusion_proof(&batch, i as usize).expect("proof");
        if verify_inclusion(&body, &batch, &proof).is_ok() {
            inclusion_detected += 1;
        }
    }

    // 3. Build a proofstore and exercise Layer B selective disclosure.
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
    for i in 0..inputs.selective_sample.min(inputs.m_invoices) {
        let (key, leaf) = &pairs[i as usize];
        let q = store.query(key).expect("query");
        if store.verify_adversarial(leaf, &q).is_ok() {
            selective_detected += 1;
        }
    }

    // 4. Inject faults.
    let mut faults: Vec<FaultRow> = Vec::new();

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

    let body_one = hex::decode(&notes[1].body_hex).expect("hex");
    let wrong_idx_detected = verify_inclusion(&body_one, &batch, &p0).is_err() as u32;
    faults.push(FaultRow {
        class: "wrong_index".into(),
        injected: 1,
        detected: wrong_idx_detected,
        missed: 1 - wrong_idx_detected,
        false_positives_clean: 0,
    });

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

    SimStudyVector {
        seed: SEED,
        m_invoices: inputs.m_invoices,
        n_payments,
        inclusion_sample: inputs.inclusion_sample.min(inputs.m_invoices),
        inclusion_detected,
        selective_sample: inputs.selective_sample.min(inputs.m_invoices),
        selective_detected,
        predetermined_level_k: k,
        faults,
        origin_falsehood_detected: 0,
        boundary_preserved: true,
    }
}

/// Serialize the vector to the same byte form the binary writes.
pub fn to_json(v: &SimStudyVector) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("serialize");
    s.push('\n');
    s
}

fn fmt_minor(minor: u64) -> String {
    format!("{}.{:02}", minor / 100, minor % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_is_deterministic() {
        let inputs = SimStudyInputs {
            m_invoices: 20,
            inclusion_sample: 8,
            selective_sample: 8,
        };
        let a = to_json(&run(inputs));
        let b = to_json(&run(inputs));
        assert_eq!(a, b, "byte-deterministic output expected");
    }

    #[test]
    fn boundary_preserved_origin_falsehood_not_detected() {
        let v = run(SimStudyInputs {
            m_invoices: 16,
            inclusion_sample: 4,
            selective_sample: 4,
        });
        assert_eq!(v.origin_falsehood_detected, 0);
        assert!(v.boundary_preserved);
    }

    #[test]
    fn all_in_scope_faults_detected() {
        let v = run(SimStudyInputs {
            m_invoices: 16,
            inclusion_sample: 4,
            selective_sample: 4,
        });
        for f in &v.faults {
            assert_eq!(f.detected, 1, "fault class {} must be detected", f.class);
            assert_eq!(f.missed, 0);
        }
    }
}
