# VEIL-PQ-1

**Status:** DRAFT (target/v1). **NOT IMPLEMENTED** — no PQ code exists
anywhere in any of the 5 repos today.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §8.

## Target (v1) scheme

Default: classical ephemeral key exchange + ML-KEM-768, used only for key
establishment/refresh, never per data packet. Three policy modes:
`PQ_REQUIRED` (no user IP frame before hybrid confirmation — hard invariant),
`PQ_PREFERRED` (attempt hybrid, fallback only if explicitly configured and
suite-bound), `CLASSIC_ONLY` (explicit legacy/dev mode, never a silent
fallback). PQ material carried inside encrypted control capsules, fragmented
across records as needed. Refresh via
`CONTROL_PQ_REFRESH_OFFER/ANSWER/CONFIRM`, folding
`pq_refresh_secret = H(mlkem_shared_secret || refresh_transcript_hash)` into
the next epoch root.

## v0 (current prototype) — what actually runs today

Nothing. v0's handshake (`core/handshake_machine.go`) is purely classical
X25519 — `dh_es`, `dh_ee`, `dh_se`, `dh_static` — with no KEM term, no PQ
policy field, and no fallback/downgrade logic since there is nothing to
downgrade from. `go.mod` has no ML-KEM or post-quantum dependency.

This is squarely Phase 5 work (`docs/ROADMAP.md`), gated on `VEIL-CANON-1`
(to carry variable-length ML-KEM public keys/ciphertexts) and
`VEIL-CONTROL-1` (to carry the PQ offer/answer/confirm exchange) landing
first. Not started, no ETA.
