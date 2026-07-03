# VEIL-PQ-1

**Status:** DRAFT. Go reference helpers exist in `pq/`; runtime handshake
integration is still pending.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` section 8.

## Scheme

Default target: classical ephemeral key exchange plus ML-KEM-768 for key
establishment and refresh, never per data packet.

Policy modes:

- `PQ_REQUIRED`: no user IP frame before hybrid confirmation.
- `PQ_PREFERRED`: attempt hybrid; fallback only if explicitly configured and
  suite-bound.
- `CLASSIC_ONLY`: explicit legacy/dev mode, never silent fallback.

PQ material is carried inside encrypted control capsules. Refresh uses
`CONTROL_PQ_REFRESH_OFFER/ANSWER/CONFIRM` and folds
`pq_refresh_secret = H(mlkem_shared_secret || refresh_transcript_hash)` into
the next epoch root.

## Go Runtime State

`pq/` contains ML-KEM-768 encapsulation/decapsulation wrappers, policy-gate
helpers, and refresh-secret derivation tests. The production handshake still
uses the current classical path until the PQ control exchange and config/API
gate are wired.
