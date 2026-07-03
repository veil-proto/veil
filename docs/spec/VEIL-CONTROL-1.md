# VEIL-CONTROL-1

**Status:** DRAFT (target/v1). **NOT IMPLEMENTED** as a general layer — v0
folds the same functionality directly into `engine.go`'s state machine
instead of separate encrypted control frames. See Appendix.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §13.

## Target (v1) scheme

Control frames, encrypted inside VEIL records, using `VEIL-CANON-1` encoding
when they carry security-relevant state:
`CONTROL_REKEY_PREPARE/COMMIT`, `CONTROL_PQ_OFFER/ANSWER/CONFIRM`,
`CONTROL_PQ_REFRESH_OFFER/ANSWER/CONFIRM`, `CONTROL_PATH_CHALLENGE/RESPONSE`,
`CONTROL_PMTU_PROBE/ACK`, `CONTROL_CLOSE`, `CONTROL_STATS_OPTIONAL`.

## v0 (current prototype) — what actually runs today

None of these exist as a distinct frame type or generic control-frame
concept. Instead, each piece of functionality is hand-coded directly into
`engine/engine.go`'s handshake/session state machine and dedicated files:

- **Rekey**: no `CONTROL_REKEY_PREPARE`/`COMMIT` handshake — a rekey is just
  a fresh Msg1/Msg2 exchange (`startInitiatorHandshake`/`handleHandshake` in
  `engine.go`) using the existing current/previous session grace mechanism
  (`Peer.Promote`, `session.go`) to make the transition seamless. This is
  functionally similar in outcome (graceful key rotation) but structurally
  very different (full handshake replay vs. a lightweight in-session control
  message).
- **PQ offer/answer/confirm, PQ refresh**: no PQ exists in v0 at all — see
  `VEIL-PQ-1.md`.
- **Path challenge/response**: no dedicated path-validation message; v0
  trusts "packet passed AEAD from a new source address" as sufficient proof
  during roaming (`NotePath` in `peer.go`) — see `VEIL-TOKENS-1.md`'s
  discussion of path tokens.
- **PMTU probe/ack**: v0 *does* have working PMTU probing
  (`engine/pmtu.go`), but it's implemented as plain probe packets on the
  transport path with size-ladder logic in the engine, not as a distinct
  encrypted `CONTROL_PMTU_PROBE`/`CONTROL_PMTU_ACK` frame type — functionally
  present, structurally different.
- **Close**: no explicit `CONTROL_CLOSE` signal exists — a peer/session
  simply stops responding and the 90s silent-tunnel watchdog
  (`engine.go`/`session.go`) eventually detects it and forces a fresh
  handshake. There's no graceful "I'm going away" notification on the wire.
- **Stats**: `Engine.Stats()` (`engine/stats.go`) exists but is a local
  in-process API surface (used by the Windows control-pipe `status`
  command), not anything transmitted between VEIL peers on the wire.

Building an actual generic encrypted control-frame layer is Phase 4 work,
gated on `VEIL-CANON-1` (Phase 2/3) landing first. The mesh workstream
(`VEIL-MESH-1.md`) needs a narrow one-off frame type (`MESH_INTRO`) sooner
than that, deliberately scoped to avoid depending on this larger redesign.
