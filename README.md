# triple-entry-evidence-bsv

BSV-native implementation of the Triple-Entry Evidence (TEA) protocol: hierarchical sub-keys on the BSV curve, ECDH-derived bilateral linkage tags, per-field SHA-256 commitments, and scoped signed disclosure envelopes — with notes anchored on BSV through two patented layers:

- **Layer A — Merkle Proof Entity** (WO 2022/100946 A1): proves a target data item of a BSV transaction is present in a BSV block via a BSV-canonical double-SHA256 Merkle proof terminating in the validated BSV block header chain.
- **Layer B — Selective Verification / proof-sharding** (WO 2025/119666 A1): divides each Merkle proof into non-overlapping shards keyed on BSV transaction attributes (txid, in/out flag, in/out position, locking script, unlocking script, amount in minor units, position-in-block); a query returns only the queried record's shard.

Selective disclosure is the privacy mechanism. The disclosure envelope releases one field key + value to one named verifier under explicit expiry; everything else stays private.

## Layout

| Crate | Role |
|---|---|
| `crates/bsv` | BSV double-SHA256 primitive; internal-LE / display-BE helpers |
| `crates/bsvcurve` | BSV curve arithmetic, ECDSA (low-S RFC 6979 deterministic), ECDH, HKDF-SHA-256 |
| `crates/tea` | TEA protocol: sub-keys, key material, per-field commitments, note body, sign/verify |
| `crates/merkle` | Layer A: Merkle Proof Entity on the BSV block Merkle convention |
| `crates/proofstore` | Layer B: Selective Verification index over BSV transaction attributes |
| `crates/anchor` | Batch TEA notes into a Merkle root and record the BSV anchor envelope |
| `crates/disclosure` | Scoped signed disclosure envelope (one field key + value per envelope) |
| `crates/cli` | `tea-bsv` CLI (selftest, reproduce, worked-example, anchor, prove, verify, query, disclose) |
| `crates/simstudy` | `tea-bsv-simstudy` synthetic-population evaluation |

## Quick start

```sh
cargo build --release
cargo test --workspace
cargo run --release -p tee-cli -- selftest
cargo run --release -p tee-cli -- worked-example
cargo run --release -p tee-cli -- reproduce
cargo run --release -p tee-simstudy -- -m 200
```

`tea-bsv reproduce` regenerates every committed deterministic vector under `vectors/` and diffs it byte-for-byte against the committed copy. Any drift fails the gate.

## What this repository is and is not

**It is** the BSV-native, Rust workspace implementation of the TEA evidence protocol anchored on BSV through the two named patents. Every reported number is produced by running this code.

**It is not** a port of the parent project `triple-entry-evidence` and does not aim to bit-reproduce that project's Appendix C vectors. It is an independent reimplementation: the curve narration, byte-level layouts, and worked-example outputs are this repository's own.

## Boundary

The system proves **presence + integrity + selective disclosure** of records anchored on BSV. It does not detect a record entered falsely **at origin** in an internally consistent population. That boundary is asserted by an explicit negative test in `crates/simstudy` (`origin_falsehood_detected = 0`).

## License

MIT. See [`LICENSE`](LICENSE).
