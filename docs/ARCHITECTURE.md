# Architecture

This document is the architectural reference engineers should read first.

## Two layers over BSV

```
                ┌─────────────────────────────────────────────┐
                │  CLI / disclosure envelopes                 │   cli / disclosure
                ├─────────────────────────────────────────────┤
                │  BSV anchoring of TEA notes                 │   anchor
                ├─────────────────────────────────────────────┤
                │  TEA protocol (sub-keys, ECDH, commits)     │   tea
                ├─────────────────────────────────────────────┤
   Layer B      │  Selective Verification / proof-sharding    │   proofstore
                ├─────────────────────────────────────────────┤
   Layer A      │  Merkle Proof Entity (BSV block Merkle)     │   merkle
                ├─────────────────────────────────────────────┤
                │  BSV curve + BSV double-SHA256              │   bsvcurve / bsv
                └─────────────────────────────────────────────┘
                                       ↓ anchors to
                              BSV block header chain
```

Verification climbs from a verifier query at the top down to a BSV block-header Merkle root at the bottom. The proof server (`proofstore`) serves **availability**, never trust. **No verifier ever accepts a result that has not terminated in a BSV-anchored Merkle root.**

## TEA protocol (`tea`)

The protocol turns a bilateral invoice / payment relationship into a verifiable public-evidence object:

1. Each party has a master scalar on the BSV curve.
2. Per-note **sub-keys**: `sk_i = sk_master + H_n(sk_master_be || u32_be(i)) mod n`; `pk_i = sk_i * G` on the BSV curve.
3. ECDH on the sub-keys produces shared `S` (big-endian affine x of the shared point).
4. `K_master = HKDF-Extract(salt = "TEA-v1", ikm = S)`; linkage tags `L_inv = HKDF-Expand(K_master, "inv-tag")` and `L_pay = HKDF-Expand(K_master, "pay-tag")`.
5. Field keys `K_field = HKDF-Expand(K_master, "commit" || u8_len(note_id) || note_id || u8_len(label) || label)`; commitments `C_field = SHA256(K_field || u8_len(label) || label || u32_be(len(value)) || value)`.
6. Note body bundles `(version || kind_marker || primary_tag || secondary_tag || issuer_pk || counterparty_pk || u8(num_fields) || C_1..C_n)` and is signed by `sk_A_i` (deterministic ECDSA, low-S enforced).

## Layer A — Merkle Proof Entity (`merkle` + `bsv`)

WO 2022/100946 A1. BSV-canonical Merkle tree:

- `H = double_sha256` for both leaves and internal nodes.
- Odd-node rule (BSV convention): on an odd level, the last node is duplicated and concatenated with itself before hashing.
- Proof = `(leaf_index, total_leaves, [sibling_hashes])`; reconstruction follows the binary path of `leaf_index`.
- Tests include round-trip property tests against synthetic trees AND a real BSV mainnet block fixture under `vectors/merkle/bsv_block_v1.json`.

## Layer B — Selective Verification (`proofstore`)

WO 2025/119666 A1, claims 1–12.

| Claim | What the crate exposes |
|---|---|
| 1 | `ProofStore::anchor(index_keys + leaves, k) -> Hash` (the Merkle root, anchored on BSV by the caller) |
| 2–3 | `StoredProof` type; non-overlapping division at the predetermined level `k` |
| 4 | Index built from the same on-chain attributes used to publish proof-assistance |
| 5–6 | Index schema: `IndexKey { txid_be, in_or_out, position, locking_script_hex, unlocking_script_hex, amount (minor units), block_position }` |
| 7 | The function used to determine the proof is fixed as BSV double-SHA256 |
| 8 | `ProofAssistance` = node labels at the predetermined level `k` (public on BSV; verifier reconstructs from there up) |
| 9–11 | Optional homomorphic compression of the level-`k` labels on the BSV curve — opt-in `TrustedOperational` mode only |
| 12 | `ProofStore::query(index_key) -> StoredProof` returns only the queried record's fragment |

Two assurance postures:

- `ReconstructionMode::Adversarial` (default; the only mode the audit path accepts).
- `ReconstructionMode::TrustedOperational` (opt-in; never accepted by audit).

## BSV anchoring (`anchor`)

A batch of TEA notes is hashed leaf-by-leaf into BSV double-SHA256 leaves, combined into a single BSV-canonical Merkle root, and recorded together with the BSV transaction identifier of the data-carrier output that publishes the root. Amounts are in **minor units**.

## Scoped disclosure (`disclosure`)

The disclosure envelope releases exactly one field key + value to one named verifier under an explicit expiry and engagement binding. The verifier checks the issuer's signature, recomputes the per-field commitment from the released key and value, and matches it against the commitment on the published note body. Past-expiry envelopes are rejected before signature checking.

The signed authorisation binds: `note_id || field_label || H(K_field) || verifier_id || engagement_id || purpose || u64(expiry) || nonce`.

## Determinism

- Worked-example outputs (`vectors/tea/worked_example_v1.json`) are bit-deterministic from the fixed master scalars `0x11…11` and `0x22…22`.
- Simulation outputs use `ChaCha20Rng` seeded with `SEED = 2_026_053_003`.
- `tea-bsv reproduce` regenerates every committed vector and diffs them.

## What this system does not do

1. It does not prove values are truthful or that any economic event occurred.
2. It does not detect a record entered falsely **at origin** in an internally consistent population (`origin_falsehood_detected = 0` is asserted in `simstudy`).
3. It does not bind classification, recognition, or population-completeness judgements.
4. It makes no claim of legal admissibility in any jurisdiction.
