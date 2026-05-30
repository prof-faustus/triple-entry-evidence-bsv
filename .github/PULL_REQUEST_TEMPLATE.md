# Pull request

## Summary

<!-- One paragraph describing the change and why. -->

## Change scope

- [ ] Source under `crates/`
- [ ] Vectors under `vectors/`
- [ ] Docs under `docs/`
- [ ] CI / build configuration

## BSV-only invariants preserved

- [ ] No source, comment, doc, dependency, lockfile entry, fixture, or example data introduces text that names or implies a chain, protocol, or ecosystem outside BSV.
- [ ] All amounts are in **minor units**.
- [ ] The curve is referred to only as the BSV curve; no external attribution added.

## Gates run locally

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `tea-bsv selftest`
- [ ] `tea-bsv reproduce`
- [ ] `tea-bsv-simstudy -m 200 --vector-out /tmp/check.json` diffs byte-equal to `vectors/study/simstudy_v1.json`

## Notes for the reviewer

<!-- Anything non-obvious. -->
