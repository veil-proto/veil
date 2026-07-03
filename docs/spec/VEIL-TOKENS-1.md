# VEIL-TOKENS-1

**Status:** DRAFT (target/v1). v0 has a related but simpler mechanism — see
Appendix.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §10.

## Target (v1) scheme

Three token classes: **rendezvous token** (pre-session cheap gate,
`MAC(rv_token_secret, server_id||time_bucket||peer_hint)[:16]`, invalid ⇒
silent drop, no distinguishable failure mode), **route token** (fast
per-packet session lookup, short-lived, not a stable peer ID,
`MAC(route_token_key, epoch_id||path_id||token_slot||direction)[:16]`), and
**path token** (roaming/path validation,
`MAC(path_token_key, endpoint_family||path_id||epoch_id)[:16]`). Receivers
accept a bounded previous/current/next token window. XDP/kmod update
ordering is strict: `veild` must install a new token/window in `veil.ko`
*before* the same token is admitted in the XDP BPF map, so XDP never lets
through a token the kernel module can't yet route.

## v0 (current prototype) — what actually runs today

v0 has no token *ladder* — it has one flat mechanism that plays a role
similar to the route token, with no rendezvous or path token concept at all:

- **Tag** (`transport/tagtable.go`, `transport/crypto.go`): a fresh BLAKE2s
  digest computed per outgoing packet (`DeriveTag`) and installed into a
  shared `TagTable` for O(1) receiver-side session lookup. Conceptually the
  closest v0 analog to the target's `route_token` — it changes every packet
  (stronger un-linkability than the target's route-token windows, which
  persist across a `token_slot`), but it is not derived from an explicit
  `epoch_id`/`path_id`/`direction` structure, just a per-session tag key plus
  packet number.
- Windowing: the current receiver pre-installs tags for a bounded lookahead
  range (2048 ahead / 1024 behind, batch-slid in 512s — see
  `recvwindow.go`), which plays a similar operational role to the target's
  previous/current/next token windows, but is scoped to one session's tag
  sequence rather than a distinct token class with its own rotation policy.
- No rendezvous token exists: v0's pre-DH gate is `mac1`
  (`DeriveMac1Key`/`CalculateMac1`, documented in `VEIL-KDF-1.md`'s v0
  appendix), which is a cheap MAC check before any DH, similar in spirit to
  a rendezvous gate, but bound to `K_net`+`NID`+the sender's static key
  rather than a time-bucketed rendezvous secret. Invalid `mac1` does result
  in a silent drop today (matches the target invariant), just via a
  different mechanism.
- No path token exists: endpoint roaming (`engine/session.go`/`peer.go`) is
  handled by observing the source address a valid packet arrived on
  (`NotePath`) rather than a dedicated cryptographic path-validation token.
  This means v0's roaming trusts "a packet that passed AEAD" as sufficient
  proof of path validity, without the target's extra path-challenge/response
  step (`CONTROL_PATH_CHALLENGE`/`CONTROL_PATH_RESPONSE`, `VEIL-CONTROL-1.md`
  — not implemented in v0 either).
- No XDP exists in v0, so the XDP/kmod token update ordering requirement is
  not yet applicable to anything.
