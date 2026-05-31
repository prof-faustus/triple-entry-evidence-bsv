# Design decisions

Decisions are recorded one per section, in the order they were made. Each has a decision, a rationale, and the alternatives considered. Once recorded, decisions are not edited; superseded decisions get a new entry below.

---

## D-001 — Stack: Rust workspace, single language end-to-end
**Decision:** Build the reference implementation as a single Cargo workspace in Rust stable.
**Rationale:** Strong types for the selective-verification index schema (WO 2025/119666 claims 5–6) and for the BSV byte-order conventions pay off in correctness. A single language reduces ceremony.
**Alternatives rejected:** Mixed-language stacks add build complexity for no benefit at this scope; the parent project's Python prototype already serves the medium-agnostic readability path.

---

## D-002 — Target platform: BSV
**Decision:** The public medium is fixed as BSV. Hash is double-SHA256; Merkle tree is the BSV block Merkle tree with the standard odd-node duplication rule; endianness follows the BSV convention (internal little-endian, display big-endian); records are anchored via BSV data-carrier outputs; verification terminates in the BSV block header chain.
**Rationale:** BSV is the fixed target platform for this project.
**Consequences:** Hash is not pluggable; index schema maps directly onto BSV UTXO transaction structure; amounts are in minor units.

---

## D-003 — Curve crate: k256 with default features off
**Decision:** Use the pure-Rust `k256` crate with `default-features = false` and only `ecdh`, `ecdsa`, `sha256`, `arithmetic`, `alloc` enabled. The crate is referred to throughout the codebase as providing **the BSV curve**.
**Rationale:** `k256` is published by RustCrypto, has no chain-ecosystem dependencies, and exposes a neutral surface for scalar/point arithmetic, ECDSA, and ECDH. The explicit feature whitelist keeps optional surfaces out of the build.
**Alternatives rejected:** Other Rust bindings for the same curve either pull in chain-ecosystem packages or wrap C libraries with chain-ecosystem framing.

---

## D-004 — Protocol mirrors the parent project but recomputes its own vectors
**Decision:** Sub-key derivation, ECDH-derived linkage tags, per-field key derivation, commitment shape, and note body layout follow the parent `triple-entry-evidence` protocol exactly. The vectors produced by this workspace are recomputed by this code and are NOT intended to bit-match the parent project's Appendix C.
**Rationale:** Reusing the protocol preserves the cryptographic content of the TEA artefact. Independently recomputed vectors avoid coupling this BSV-native implementation to a separately versioned Python reference and make the audit boundary cleaner.

---

## D-005 — Predetermined level `k` for proof-assistance
**Decision:** `k = floor(log2(N) / 2)` by default; callers can pass `k` explicitly.
**Rationale:** Balanced split between per-query lower-shard bytes and one-time public assistance bytes.

---

## D-006 — Two assurance modes; audit API rejects the non-adversarial one
**Decision:** `ReconstructionMode::Adversarial` (default) reconstructs the Merkle path against public node labels and the BSV-anchored root. `ReconstructionMode::TrustedOperational` (opt-in) is reserved for the patent's optional homomorphic-compression mode on the BSV curve. The audit path rejects results from the trusted-operational mode.
**Rationale:** The two modes have different security postures. Silent fallback would launder that distinction.

---

## D-007 — Reproducibility: deterministic vectors checked on every reproduce
**Decision:** Every deterministic output the project reports has a committed vector under `vectors/` and is regenerated + diffed by `tea-bsv reproduce`.
**Rationale:** No fabricated numbers; every reported value comes from running the code. Drift fails the gate.

---

## D-008 — Disclosure envelope binds verifier, engagement, purpose, and expiry
**Decision:** The signed authorisation is `note_id || field_label || H(K_field) || verifier_id || engagement_id || purpose || u64(expiry) || nonce`. Past-expiry envelopes are rejected before signature checking. Issuance produces a self-check: the verifier-side path is exercised against the freshly-issued envelope before the file is written.
**Rationale:** Mirrors the parent project's disclosure model and gives auditors a single byte layout to recompute.
