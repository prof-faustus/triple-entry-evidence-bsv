# Security notes

## Threat model

The protocol covers three concrete threats:

1. **Post-issuance alteration of a note.** The note body is signed by the issuer's sub-key under deterministic ECDSA; the body hash is the leaf anchored on BSV. Any change to the body invalidates either the signature or the Merkle path.
2. **Selective falsification of a disclosed field.** Recipients of a disclosure envelope recompute the per-field commitment from the released `K_field` and value, and match it against the commitment on the published body. Lying about the value is rejected.
3. **Replay or scope abuse of a disclosure.** The disclosure envelope binds verifier identity, engagement identifier, purpose, and expiry. Past-expiry envelopes are rejected; cross-engagement reuse is detectable because each envelope is bound to one engagement and one verifier.

## Out of scope

- **Origin falsehood.** If both parties agree to record a fictitious transaction with internally consistent figures, the artefact records the agreed figures faithfully. The simulation study asserts this boundary as a negative test (`origin_falsehood_detected = 0`).
- **Population completeness.** The artefact proves presence and integrity of recorded notes; it does not bind that the population is complete.
- **Recognition / classification.** Accounting policy judgements are not bound by the artefact.
- **Legal admissibility.** Admissibility depends on jurisdiction-specific rules and is not asserted by this code.

## Curve choice

All curve operations are stated as operations on **the BSV curve**. The arithmetic is provided by the pure-Rust `k256` crate (RustCrypto). The `schnorr` feature is deliberately disabled so no chain-fork signature scheme code compiles in.

## Determinism guarantees

ECDSA signatures use deterministic nonce generation (RFC 6979) with low-S canonicalisation enforced at the API surface. Two signatures over the same prehash under the same key are byte-identical.

## Side-channel posture

The implemented layers do not handle long-lived secrets. The cryptographic primitives in scope are public-input hash composition (SHA-256), short-lived ECDH on per-note sub-keys, and deterministic ECDSA. No secret-dependent branching exists in this workspace. The `k256` crate's scalar multiplication is constant-time on the affine path used here.
