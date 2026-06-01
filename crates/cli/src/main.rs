// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! `tea-bsv` — Triple-entry evidence on BSV, command-line interface.
//!
//! Subcommands:
//! - `tea-bsv selftest` — exercise every implemented layer end to end.
//! - `tea-bsv reproduce` — regenerate every deterministic vector and diff
//!   against the committed expected outputs.
//! - `tea-bsv worked-example` — print the canonical worked-example values
//!   produced by the TEA protocol on the BSV curve (refimpl analogue, but on
//!   the BSV curve — these vectors are independent of the parent
//!   triple-entry-evidence project's Appendix C).
//! - `tea-bsv anchor` — read a JSON file of signed notes, build the BSV
//!   Merkle root over their bodies, and print the root and proof-assistance.
//! - `tea-bsv prove` — produce an inclusion bundle for one note in a batch.
//! - `tea-bsv verify` — verify an inclusion bundle.
//! - `tea-bsv query` — exercise the selective-verification proofstore.
//! - `tea-bsv disclose` — issue a scoped disclosure envelope for one field.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use tee_anchor::{build_batch, build_inclusion_proof, verify_inclusion, AnchoredBatch};
use tee_bsv::{double_sha256, Hash};
use tee_bsvcurve::{
    hkdf_expand_one_block, hkdf_extract, sha256, BsvPoint, BsvScalar,
};
use tee_disclosure::{issue_disclosure, verify_disclosure};
use tee_merkle::MerkleProof;
use tee_proofstore::{InOrOut, IndexKey, ProofStore, ReconstructionMode};
use tee_tea::{
    build_note_body, commit_one, derive_key_material, derive_subkey, sign_note, verify_note,
    Field, NoteBuilderInputs, NoteKind, SignedNote,
};

#[derive(Parser)]
#[command(name = "tea-bsv", version, about = "Triple-entry evidence on BSV")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Selftest,
    Reproduce,
    WorkedExample,
    Anchor {
        /// JSON file containing an array of signed notes.
        #[arg(long)]
        notes: PathBuf,
        /// Display-orientation BSV txid that carries the root.
        #[arg(long)]
        bsv_anchor_txid_be: String,
        /// Anchor output amount in minor units.
        #[arg(long, default_value_t = 1)]
        anchor_minor_units: u64,
        #[arg(long, default_value_t = 0)]
        batch_id: u64,
        #[arg(long)]
        out: PathBuf,
    },
    Prove {
        #[arg(long)]
        batch: PathBuf,
        #[arg(long)]
        notes: PathBuf,
        #[arg(long)]
        leaf_index: usize,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long)]
        bundle: PathBuf,
    },
    Query {
        /// Number of synthetic leaves to anchor in the proofstore demo.
        #[arg(long, default_value_t = 64)]
        n: usize,
    },
    Disclose {
        #[arg(long)]
        sk_hex: String,
        #[arg(long)]
        note_id: String,
        #[arg(long)]
        field_label: String,
        #[arg(long)]
        field_value: String,
        #[arg(long)]
        k_field_hex: String,
        #[arg(long)]
        verifier_id: String,
        #[arg(long)]
        engagement_id: String,
        #[arg(long)]
        purpose: String,
        #[arg(long)]
        expiry_unix: u64,
        #[arg(long, default_value = "00000000000000000000000000000000")]
        nonce_hex: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Derive the one-time shared payment public key PK_once = M_payee + t*G
    /// from the additive-tweak scheme (04 §4.20-4.28). Emits ONLY public values
    /// (derived_pubkey, salt_commitment, A/B ordering); never S, t, salt_det, or
    /// any private scalar (REQ-WIRE-0141).
    DeriveSharedAddress {
        /// Deriving party's master private scalar (32-byte hex, demo backend).
        #[arg(long)]
        sk_hex: String,
        /// The OTHER party's master public key for ECDH (33-byte compressed hex).
        #[arg(long)]
        remote_pub_hex: String,
        /// M_payee — the tweak target whose key becomes PK_once (33-byte hex).
        #[arg(long)]
        payee_pub_hex: String,
        /// The deterministic-CBOR derivation context DC (hex), built by the caller.
        #[arg(long)]
        dc_hex: String,
        /// Salt rule: "context" (salt=SHA256(DC)) or "shared-secret" (salt=SHA256(0x53||S)).
        #[arg(long, default_value = "context")]
        salt_rule: String,
        /// Network selector for the P2PKH address version byte.
        #[arg(long, default_value = "regtest")]
        network: String,
    },
    /// Build a signed invoice or payment note: per-field commitments over the
    /// canonical field values, the linkage tag(s), the note body, and the
    /// signature. Field VALUES stay private (only labels appear in the output);
    /// a payment note's L_pay binds to the linked invoice's L_inv under the same S.
    BuildNote {
        /// Issuer's signing sub-key scalar (32-byte hex, demo backend).
        #[arg(long)]
        sk_hex: String,
        /// Counterparty's sub-key public point (33-byte compressed hex).
        #[arg(long)]
        counterparty_pub_hex: String,
        /// Note identifier (binds the per-field key derivation).
        #[arg(long)]
        note_id: String,
        /// Note kind: "invoice" or "payment".
        #[arg(long, default_value = "invoice")]
        kind: String,
        /// JSON file: an array of {"label":..., "value":...} field objects.
        #[arg(long)]
        fields_file: PathBuf,
        /// Output path for the SignedNote JSON.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProofBundle {
    version: u32,
    batch: AnchoredBatch,
    note_body_hex: String,
    proof: MerkleProof,
}

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Selftest => cmd_selftest(),
        Cmd::Reproduce => cmd_reproduce(),
        Cmd::WorkedExample => cmd_worked_example(),
        Cmd::Anchor {
            notes,
            bsv_anchor_txid_be,
            anchor_minor_units,
            batch_id,
            out,
        } => cmd_anchor(
            &notes,
            bsv_anchor_txid_be,
            anchor_minor_units,
            batch_id,
            &out,
        ),
        Cmd::Prove {
            batch,
            notes,
            leaf_index,
            out,
        } => cmd_prove(&batch, &notes, leaf_index, &out),
        Cmd::Verify { bundle } => cmd_verify(&bundle),
        Cmd::Query { n } => cmd_query(n),
        Cmd::Disclose {
            sk_hex,
            note_id,
            field_label,
            field_value,
            k_field_hex,
            verifier_id,
            engagement_id,
            purpose,
            expiry_unix,
            nonce_hex,
            out,
        } => cmd_disclose(
            sk_hex,
            note_id,
            field_label,
            field_value,
            k_field_hex,
            verifier_id,
            engagement_id,
            purpose,
            expiry_unix,
            nonce_hex,
            &out,
        ),
        Cmd::DeriveSharedAddress {
            sk_hex,
            remote_pub_hex,
            payee_pub_hex,
            dc_hex,
            salt_rule,
            network,
        } => cmd_derive_shared_address(sk_hex, remote_pub_hex, payee_pub_hex, dc_hex, salt_rule, network),
        Cmd::BuildNote {
            sk_hex,
            counterparty_pub_hex,
            note_id,
            kind,
            fields_file,
            out,
        } => cmd_build_note(sk_hex, counterparty_pub_hex, note_id, kind, &fields_file, &out),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_selftest() -> Result<(), String> {
    println!("tea-bsv selftest");
    println!("================");

    // 1. BSV double-SHA256 known vector.
    let h = double_sha256(b"");
    let want = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
    if hex::encode(h) != want {
        return Err("BSV double-SHA256 known vector mismatch".into());
    }
    println!("  [ok]  bsv         : double-SHA256 known-vector matches");

    // 2. TEA round-trip: derive subkeys, ECDH, commit, sign, verify.
    let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).map_err(|e| e.to_string())?;
    let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).map_err(|e| e.to_string())?;
    let a = derive_subkey(&sk_a, 1).map_err(|e| e.to_string())?;
    let b = derive_subkey(&sk_b, 1).map_err(|e| e.to_string())?;
    let mat = derive_key_material(&a.scalar, &b.point);
    let mat_b = derive_key_material(&b.scalar, &a.point);
    if mat.shared_s != mat_b.shared_s {
        return Err("ECDH agreement failed".into());
    }
    println!("  [ok]  tea         : ECDH agreement; subkey derivation deterministic");

    // 3. Commit, build body, sign, verify, tamper-reject.
    let fields = [
        ("InvID", "INV-0001"),
        ("Curr", "EUR"),
        ("Net", "10000.00"),
        ("Gross", "12100.00"),
    ];
    let cs: Vec<_> = fields
        .iter()
        .map(|(l, v)| commit_one(&mat.k_master, "INV-0001", l, v).1)
        .collect();
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
    verify_note(&a.point, &body, &sig).map_err(|e| e.to_string())?;
    if h != double_sha256(&body) {
        return Err("body hash mismatch".into());
    }
    println!("  [ok]  tea         : sign + verify + leaf-hash chain");

    // 4. Layer A: Merkle round-trip.
    let leaves: Vec<Hash> = (0..8u32).map(|i| double_sha256(&i.to_be_bytes())).collect();
    let root = tee_merkle::merkle_root_of_leaves(&leaves).map_err(|e| e.to_string())?;
    let p = tee_merkle::build_proof(&leaves, 3).map_err(|e| e.to_string())?;
    tee_merkle::verify_proof(&p, &leaves[3], &root).map_err(|e| e.to_string())?;
    println!("  [ok]  merkle      : Layer A inclusion proof verifies");

    // 5. Layer B: proofstore anchor + query + adversarial verify.
    let pairs: Vec<(IndexKey, Hash)> = (0..16u64)
        .map(|i| {
            (
                IndexKey {
                    txid_be: format!("{:064x}", i),
                    in_or_out: InOrOut::Output,
                    position: 0,
                    locking_script_hex: "76a9".into(),
                    unlocking_script_hex: String::new(),
                    amount: 1000 + i,
                    block_position: i,
                },
                double_sha256(&(i as u32).to_be_bytes()),
            )
        })
        .collect();
    let store = ProofStore::anchor(pairs.clone(), None).map_err(|e| e.to_string())?;
    let q = store.query(&pairs[5].0).map_err(|e| e.to_string())?;
    store
        .verify_adversarial(&pairs[5].1, &q)
        .map_err(|e| e.to_string())?;
    println!(
        "  [ok]  proofstore  : Layer B query + adversarial reconstruction (k={})",
        store.predetermined_level()
    );
    // Trusted-operational mode is opt-in only and never accepted by audit:
    let _audit_mode = ReconstructionMode::Adversarial;

    println!();
    println!("selftest passed: 5/5 checks");
    Ok(())
}

fn cmd_reproduce() -> Result<(), String> {
    println!("tea-bsv reproduce");
    println!("=================");

    let workspace_root = workspace_root();
    let vectors = workspace_root.join("vectors");

    // 1. merkle/bsv_block_v1.json — real BSV mainnet block, two txids.
    let path = vectors.join("merkle").join("bsv_block_v1.json");
    let s = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    #[derive(serde::Deserialize)]
    struct BsvBlock {
        txids_display_be: Vec<String>,
        expected_merkle_root_display_be: String,
    }
    let v: BsvBlock = serde_json::from_str(&s).map_err(|e| e.to_string())?;
    let to_le = |hex_be: &str| -> Hash {
        let mut v = hex::decode(hex_be).unwrap();
        v.reverse();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };
    let leaves: Vec<Hash> = v.txids_display_be.iter().map(|h| to_le(h)).collect();
    let mut root = tee_merkle::merkle_root_of_leaves(&leaves).map_err(|e| e.to_string())?;
    root.reverse();
    let recomputed = hex::encode(root);
    if recomputed != v.expected_merkle_root_display_be {
        return Err(format!(
            "merkle.bsv_block.v1 mismatch: recomputed={recomputed} expected={}",
            v.expected_merkle_root_display_be
        ));
    }
    println!("  [ok]  merkle.bsv_block.v1");

    // 2. tea/worked_example_v1.json — TEA worked example on the BSV curve.
    let path = vectors.join("tea").join("worked_example_v1.json");
    let want = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let have = produce_worked_example_json()?;
    if want.trim() != have.trim() {
        return Err("tea.worked_example.v1 mismatch (re-run worked-example and diff)".into());
    }
    println!("  [ok]  tea.worked_example.v1");

    // 3. study/simstudy_v1.json — synthetic-population study at fixed inputs.
    let path = vectors.join("study").join("simstudy_v1.json");
    let want = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v = tee_simstudy::run(tee_simstudy::SimStudyInputs {
        m_invoices: 200,
        inclusion_sample: 64,
        selective_sample: 64,
    });
    let have = tee_simstudy::to_json(&v);
    if want != have {
        return Err("study.simstudy.v1 mismatch (re-run simstudy and diff)".into());
    }
    println!(
        "  [ok]  study.simstudy.v1 (M={}, inclusion={}/{}, selective={}/{}, all in-scope faults detected)",
        v.m_invoices, v.inclusion_detected, v.inclusion_sample, v.selective_detected, v.selective_sample,
    );

    println!();
    println!("reproduce passed: 3 committed vector(s) match");
    Ok(())
}

fn cmd_worked_example() -> Result<(), String> {
    let json = produce_worked_example_json()?;
    println!("{json}");
    Ok(())
}

fn produce_worked_example_json() -> Result<String, String> {
    // Same protocol shape as the parent project's refimpl, but executed on the
    // BSV curve via tee-bsvcurve. The hex outputs are independent of the parent
    // project's Appendix C.
    let sk_a = BsvScalar::from_bytes(&[0x11u8; 32]).map_err(|e| e.to_string())?;
    let sk_b = BsvScalar::from_bytes(&[0x22u8; 32]).map_err(|e| e.to_string())?;
    let a = derive_subkey(&sk_a, 1).map_err(|e| e.to_string())?;
    let b = derive_subkey(&sk_b, 1).map_err(|e| e.to_string())?;
    let mat = derive_key_material(&a.scalar, &b.point);
    let fields = [
        ("InvID", "INV-0001"),
        ("Curr", "EUR"),
        ("Net", "10000.00"),
        ("Gross", "12100.00"),
        ("Tax", "2100.00"),
        ("Due", "2026-04-30"),
        ("Terms", "NET30"),
        ("MeasPol", "STD-ROUND"),
    ];
    let mut kfs = Vec::new();
    let mut cs = Vec::new();
    for (l, v) in &fields {
        let (kf, c) = commit_one(&mat.k_master, "INV-0001", l, v);
        kfs.push((l.to_string(), hex::encode(kf)));
        cs.push((l.to_string(), hex::encode(c)));
    }
    let raw_cs: Vec<_> = cs
        .iter()
        .map(|(_, h)| {
            let v = hex::decode(h).unwrap();
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        })
        .collect();
    let body = build_note_body(&NoteBuilderInputs {
        kind: NoteKind::Invoice,
        version: 1,
        primary_tag: mat.l_inv,
        secondary_tag: [0u8; 32],
        issuer_pk: a.point,
        counterparty_pk: b.point,
        commitments: &raw_cs,
    });
    let (body_hash, sig) = sign_note(&a.scalar, &body);

    #[derive(serde::Serialize)]
    struct Out {
        sk_master_a_hex: String,
        sk_master_b_hex: String,
        sk_a_1_hex: String,
        pk_a_1_hex: String,
        sk_b_1_hex: String,
        pk_b_1_hex: String,
        shared_s_hex: String,
        k_master_hex: String,
        l_inv_hex: String,
        l_pay_hex: String,
        k_fields: Vec<(String, String)>,
        c_fields: Vec<(String, String)>,
        body_hex: String,
        body_len: usize,
        body_hash_hex: String,
        signature_hex: String,
    }
    let out = Out {
        sk_master_a_hex: hex::encode([0x11u8; 32]),
        sk_master_b_hex: hex::encode([0x22u8; 32]),
        sk_a_1_hex: hex::encode(a.scalar.to_bytes()),
        pk_a_1_hex: hex::encode(a.point.to_compressed()),
        sk_b_1_hex: hex::encode(b.scalar.to_bytes()),
        pk_b_1_hex: hex::encode(b.point.to_compressed()),
        shared_s_hex: hex::encode(mat.shared_s),
        k_master_hex: hex::encode(mat.k_master),
        l_inv_hex: hex::encode(mat.l_inv),
        l_pay_hex: hex::encode(mat.l_pay),
        k_fields: kfs,
        c_fields: cs,
        body_hex: hex::encode(&body),
        body_len: body.len(),
        body_hash_hex: hex::encode(body_hash),
        signature_hex: hex::encode(sig),
    };
    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

fn cmd_anchor(
    notes_path: &PathBuf,
    bsv_anchor_txid_be: String,
    anchor_minor_units: u64,
    batch_id: u64,
    out: &PathBuf,
) -> Result<(), String> {
    let s = fs::read_to_string(notes_path).map_err(|e| e.to_string())?;
    let notes: Vec<SignedNote> = serde_json::from_str(&s).map_err(|e| e.to_string())?;
    let batch = build_batch(batch_id, &notes, bsv_anchor_txid_be, anchor_minor_units)
        .map_err(|e| e.to_string())?;
    let j = serde_json::to_string_pretty(&batch).map_err(|e| e.to_string())?;
    fs::write(out, j).map_err(|e| e.to_string())?;
    println!("anchor: wrote {}", out.display());
    Ok(())
}

fn cmd_prove(
    batch_path: &PathBuf,
    notes_path: &PathBuf,
    leaf_index: usize,
    out: &PathBuf,
) -> Result<(), String> {
    let b: AnchoredBatch =
        serde_json::from_str(&fs::read_to_string(batch_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let notes: Vec<SignedNote> =
        serde_json::from_str(&fs::read_to_string(notes_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let proof = build_inclusion_proof(&b, leaf_index).map_err(|e| e.to_string())?;
    let bundle = ProofBundle {
        version: 1,
        batch: b,
        note_body_hex: notes
            .get(leaf_index)
            .ok_or("leaf_index out of range")?
            .body_hex
            .clone(),
        proof,
    };
    fs::write(
        out,
        serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("prove: wrote {}", out.display());
    Ok(())
}

fn cmd_verify(bundle_path: &PathBuf) -> Result<(), String> {
    let b: ProofBundle =
        serde_json::from_str(&fs::read_to_string(bundle_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let body = hex::decode(&b.note_body_hex).map_err(|e| e.to_string())?;
    verify_inclusion(&body, &b.batch, &b.proof).map_err(|e| e.to_string())?;
    println!("verify OK");
    Ok(())
}

fn cmd_query(n: usize) -> Result<(), String> {
    let pairs: Vec<(IndexKey, Hash)> = (0..n as u64)
        .map(|i| {
            (
                IndexKey {
                    txid_be: format!("{:064x}", i),
                    in_or_out: InOrOut::Output,
                    position: 0,
                    locking_script_hex: "76a9".into(),
                    unlocking_script_hex: String::new(),
                    amount: 1000 + i,
                    block_position: i,
                },
                double_sha256(&(i as u32).to_be_bytes()),
            )
        })
        .collect();
    let store = ProofStore::anchor(pairs.clone(), None).map_err(|e| e.to_string())?;
    println!(
        "anchored {} leaves; k = {}",
        store.leaf_count(),
        store.predetermined_level()
    );
    for i in [0, n / 2, n - 1] {
        let q = store.query(&pairs[i].0).map_err(|e| e.to_string())?;
        store
            .verify_adversarial(&pairs[i].1, &q)
            .map_err(|e| e.to_string())?;
        println!("  query #{i}: lower_shard_len={}", q.lower_shard_hex.len());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_disclose(
    sk_hex: String,
    note_id: String,
    field_label: String,
    field_value: String,
    k_field_hex: String,
    verifier_id: String,
    engagement_id: String,
    purpose: String,
    expiry_unix: u64,
    nonce_hex: String,
    out: &PathBuf,
) -> Result<(), String> {
    let sk_bytes = hex::decode(&sk_hex).map_err(|e| e.to_string())?;
    if sk_bytes.len() != 32 {
        return Err("sk_hex must be 64 hex chars (32 bytes)".into());
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let sk = BsvScalar::from_bytes(&sk_arr).map_err(|e| e.to_string())?;
    let pk = sk.mul_base();
    let kf_bytes = hex::decode(&k_field_hex).map_err(|e| e.to_string())?;
    if kf_bytes.len() != 32 {
        return Err("k_field_hex must be 32 bytes".into());
    }
    let mut kf = [0u8; 32];
    kf.copy_from_slice(&kf_bytes);
    let nonce = hex::decode(&nonce_hex).map_err(|e| e.to_string())?;
    let env = issue_disclosure(
        &sk,
        &pk,
        note_id,
        field_label.clone(),
        &kf,
        field_value,
        verifier_id,
        engagement_id,
        purpose,
        expiry_unix,
        &nonce,
    )
    .map_err(|e| e.to_string())?;
    // Quick sanity self-check: verify the freshly-issued envelope against its
    // own recomputed commitment, modulo expiry.
    let expected = tee_tea::commit_field(&kf, &field_label, &env.disclosed_value);
    verify_disclosure(&env, &expected, 0).map_err(|e| e.to_string())?;
    fs::write(
        out,
        serde_json::to_string_pretty(&env).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("disclose: wrote {}", out.display());
    Ok(())
}

fn decode_32(label: &str, s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| format!("{label}: {e}"))?;
    if v.len() != 32 {
        return Err(format!("{label} must be 32 bytes, got {}", v.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

fn decode_33(label: &str, s: &str) -> Result<[u8; 33], String> {
    let v = hex::decode(s).map_err(|e| format!("{label}: {e}"))?;
    if v.len() != 33 {
        return Err(format!("{label} must be 33 bytes, got {}", v.len()));
    }
    let mut a = [0u8; 33];
    a.copy_from_slice(&v);
    Ok(a)
}

/// One-time shared-address derivation (04 §4.20-4.28). Public outputs only.
fn cmd_derive_shared_address(
    sk_hex: String,
    remote_pub_hex: String,
    payee_pub_hex: String,
    dc_hex: String,
    salt_rule: String,
    network: String,
) -> Result<(), String> {
    use ripemd::{Digest, Ripemd160};
    let sk = BsvScalar::from_bytes(&decode_32("sk_hex", &sk_hex)?).map_err(|e| e.to_string())?;
    let remote_pub =
        BsvPoint::from_compressed(&decode_33("remote_pub_hex", &remote_pub_hex)?).map_err(|e| e.to_string())?;
    let payee_pub =
        BsvPoint::from_compressed(&decode_33("payee_pub_hex", &payee_pub_hex)?).map_err(|e| e.to_string())?;
    let dc = hex::decode(&dc_hex).map_err(|e| format!("dc_hex: {e}"))?;

    // Step 2: ECDH shared secret S = SHA-256(compressed(m_local * M_remote)).
    let p_s = remote_pub.mul_scalar(&sk);
    let s = sha256(&p_s.to_compressed());

    // Step 4: deterministic salt by the active rule.
    let salt_det = match salt_rule.as_str() {
        "context" => sha256(&dc),
        "shared-secret" => {
            let mut buf = Vec::with_capacity(1 + 32);
            buf.push(0x53);
            buf.extend_from_slice(&s);
            sha256(&buf)
        }
        other => return Err(format!("unknown salt_rule {other:?} (context|shared-secret)")),
    };
    let salt_commitment = sha256(&salt_det);

    // Step 5: tweak t = HKDF-SHA256(ikm=S, salt=salt_det, info=DC) reduced mod n.
    let prk = hkdf_extract(&salt_det, &s);
    let okm = hkdf_expand_one_block(&prk, &dc);
    let t = BsvScalar::from_bytes_reduce(&okm).map_err(|_| {
        "derived tweak is zero; caller must increment payment_index and rebuild DC".to_string()
    })?;
    let pk_once = payee_pub.add(&t.mul_base());

    // Step 6: P2PKH address = base58check(version || HASH160(PK_once)). No P2SH.
    let version_byte: u8 = match network.as_str() {
        "mainnet" => 0x00,
        "testnet" | "regtest" => 0x6f,
        other => return Err(format!("unknown network {other:?} (mainnet|testnet|regtest)")),
    };
    let pk_compressed = pk_once.to_compressed();
    let h160 = {
        let mut r = Ripemd160::new();
        r.update(sha256(&pk_compressed));
        r.finalize()
    };
    let address_text = bs58::encode(h160).with_check_version(version_byte).into_string();

    // canonical A/B ordering over the two master public keys (Step 1), for transparency.
    let (a, b) = {
        let m_remote = remote_pub.to_compressed();
        let m_payee = payee_pub.to_compressed();
        if m_payee <= m_remote { (m_payee, m_remote) } else { (m_remote, m_payee) }
    };

    // Public outputs ONLY — never S, t, salt_det, or any private scalar (REQ-WIRE-0141).
    #[derive(serde::Serialize)]
    struct Out {
        derived_pubkey_hex: String,
        address_text: String,
        salt_commitment_hex: String,
        master_pub_a_hex: String,
        master_pub_b_hex: String,
    }
    let out = Out {
        derived_pubkey_hex: hex::encode(pk_compressed),
        address_text,
        salt_commitment_hex: hex::encode(salt_commitment),
        master_pub_a_hex: hex::encode(a),
        master_pub_b_hex: hex::encode(b),
    };
    println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
    Ok(())
}

/// Build a signed invoice/payment note (5.3.3/5.3.4). Field values stay private.
fn cmd_build_note(
    sk_hex: String,
    counterparty_pub_hex: String,
    note_id: String,
    kind: String,
    fields_file: &PathBuf,
    out: &PathBuf,
) -> Result<(), String> {
    let sk = BsvScalar::from_bytes(&decode_32("sk_hex", &sk_hex)?).map_err(|e| e.to_string())?;
    let cp = BsvPoint::from_compressed(&decode_33("counterparty_pub_hex", &counterparty_pub_hex)?)
        .map_err(|e| e.to_string())?;
    let note_kind = match kind.as_str() {
        "invoice" => NoteKind::Invoice,
        "payment" => NoteKind::Payment,
        other => return Err(format!("unknown kind {other:?} (invoice|payment)")),
    };
    let fields: Vec<Field> = serde_json::from_str(
        &fs::read_to_string(fields_file).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("fields_file: {e}"))?;

    let mat = derive_key_material(&sk, &cp);
    // invoice: primary=L_inv, secondary=zeros; payment: primary=L_pay, secondary=L_inv (linkage).
    let (primary_tag, secondary_tag) = match note_kind {
        NoteKind::Invoice => (mat.l_inv, [0u8; 32]),
        NoteKind::Payment => (mat.l_pay, mat.l_inv),
    };
    let commitments: Vec<[u8; 32]> = fields
        .iter()
        .map(|f| commit_one(&mat.k_master, &note_id, &f.label, &f.value).1)
        .collect();

    let issuer_pk = sk.mul_base();
    let body = build_note_body(&NoteBuilderInputs {
        kind: note_kind,
        version: 1,
        primary_tag,
        secondary_tag,
        issuer_pk,
        counterparty_pk: cp,
        commitments: &commitments,
    });
    let (body_hash, sig) = sign_note(&sk, &body);

    let note = SignedNote {
        kind: note_kind,
        version: 1,
        note_id: note_id.clone(),
        primary_tag_hex: hex::encode(primary_tag),
        secondary_tag_hex: hex::encode(secondary_tag),
        issuer_pk_hex: hex::encode(issuer_pk.to_compressed()),
        counterparty_pk_hex: hex::encode(cp.to_compressed()),
        // labels only — values stay private until disclosed (REQ-WIRE-0070).
        fields_pub: fields
            .iter()
            .map(|f| Field {
                label: f.label.clone(),
                value: String::new(),
            })
            .collect(),
        commitments_hex: commitments.iter().map(hex::encode).collect(),
        body_hex: hex::encode(&body),
        body_hash_hex: hex::encode(body_hash),
        signature_hex: hex::encode(sig),
    };
    fs::write(out, serde_json::to_string_pretty(&note).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    println!(
        "build-note: wrote {} (kind={kind}, fields={}, l_tag={})",
        out.display(),
        fields.len(),
        hex::encode(primary_tag)
    );
    Ok(())
}

fn workspace_root() -> PathBuf {
    // Resolve from CARGO_MANIFEST_DIR up to workspace root.
    let m = env!("CARGO_MANIFEST_DIR");
    let mut p = PathBuf::from(m);
    // crates/cli -> .. -> ..
    p.pop();
    p.pop();
    p
}
