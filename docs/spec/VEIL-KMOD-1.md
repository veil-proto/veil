# VEIL-KMOD-1

**Status:** DRAFT. Not implemented; no C/kernel code exists anywhere in the
five repos today. The current data plane is Go user space (`veil/engine`) via
TUN plus UDP.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` sections 3.3 and 17.

## Target Scope

`veil.ko` owns only the fast path:

- netdev and UDP RX/TX encap/decap
- route-token lookup
- record/v1 header protection apply/remove
- AEAD open/seal
- replay-window check
- allowed-routes LPM lookup
- current/previous/next epoch handling
- endpoint roaming metadata
- counters and rate-limited diagnostics

The kernel module never owns ML-KEM private state or the full handshake.
`veild` derives keys and installs session/token state through Generic Netlink:

- `VEIL_CMD_DEV_CREATE` / `VEIL_CMD_DEV_DELETE`
- `VEIL_CMD_PEER_SET` / `VEIL_CMD_PEER_DELETE`
- `VEIL_CMD_SESSION_INSTALL` / `VEIL_CMD_SESSION_ROTATE` /
  `VEIL_CMD_SESSION_DELETE`
- `VEIL_CMD_TOKEN_INSTALL` / `VEIL_CMD_TOKEN_PROMOTE`
- `VEIL_CMD_ENDPOINT_UPDATE`
- `VEIL_CMD_ALLOWEDIP_SET`
- `VEIL_CMD_STATS_GET`
- `VEIL_CMD_XDP_TOKEN_SYNC`

`SESSION_INSTALL` receives already-derived data-plane material: TX/RX AEAD
keys, nonce prefixes, route-token keys, HP keys, padding policy, replay window
size, and policy fields.

## Current Go Baseline

The Go engine is now the executable reference for the future kernel fast path:
`record/v1`, `tokens`, `engine/route_tokens.go`, `engine/fragment.go`, and
`engine/pmtu.go` define the behavior kmod must reproduce. Before starting
kmod, publish stable fixture vectors and keep downstream user-space clients
green against `github.com/veil-proto/veil@main`.
