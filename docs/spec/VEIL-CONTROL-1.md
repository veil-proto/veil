# VEIL-CONTROL-1

**Status:** DRAFT. The Go runtime can carry encrypted record/v1 `CONTROL`
frames; the full canonical control protocol is still pending.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` section 13.

## Target Scheme

Control messages are encrypted inside VEIL records as `CONTROL` inner frames.
Security-relevant state should use `VEIL-CANON-1` capsules:

- `CONTROL_REKEY_PREPARE` / `CONTROL_REKEY_COMMIT`
- `CONTROL_PQ_OFFER` / `CONTROL_PQ_ANSWER` / `CONTROL_PQ_CONFIRM`
- `CONTROL_PQ_REFRESH_OFFER` / `CONTROL_PQ_REFRESH_ANSWER` /
  `CONTROL_PQ_REFRESH_CONFIRM`
- `CONTROL_PATH_CHALLENGE` / `CONTROL_PATH_RESPONSE`
- `CONTROL_PMTU_PROBE` / `CONTROL_PMTU_ACK`
- `CONTROL_CLOSE`
- `CONTROL_STATS_OPTIONAL`

## Go Runtime State

Implemented now:

- `control/v1`: canonical control capsule helpers for deterministic encoding.
- `engine/pmtu.go`: PMTU probe/ack payloads sent inside encrypted
  record/v1 `CONTROL` frames.
- `engine/mesh.go`: `MESH_INTRO` is sent inside encrypted record/v1
  `CONTROL` frames.
- `engine/engine.go`: inbound `CONTROL` dispatch for PMTU probe/ack and
  `MESH_INTRO`.

Still pending before kmod:

- Runtime PQ offer/answer/confirm and strict PQ gate.
- Runtime epoch refresh/rekey control messages.
- Dedicated path challenge/response tokens.
- Cross-language fixture files for the canonical control capsules.

The Windows GUI control pipe is a local service API and is intentionally
separate from this peer-to-peer encrypted control layer.
