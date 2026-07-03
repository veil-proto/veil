# VEIL-KMOD-1

**Status:** DRAFT (target/v1). **NOT IMPLEMENTED** — no C/kernel code exists
anywhere in any of the 5 repos today; the entire data plane is Go
(`veil/engine`) running in user space via a TUN device.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §3.3, §17.

## Target (v1) scheme

`veil.ko` owns only the fast path: netdev, UDP RX/TX encap/decap,
route-token lookup, header protection removal/application, AEAD open/seal,
replay-window check, allowed-routes LPM lookup, current/previous/next epoch
handling, endpoint roaming metadata, counters/rate-limited diagnostics. No
ML-KEM or full handshake logic in kernel. Control via Generic Netlink:
`VEIL_CMD_DEV_CREATE/DELETE`, `VEIL_CMD_PEER_SET/DELETE`,
`VEIL_CMD_SESSION_INSTALL/ROTATE/DELETE`, `VEIL_CMD_TOKEN_INSTALL/PROMOTE`,
`VEIL_CMD_ENDPOINT_UPDATE`, `VEIL_CMD_ALLOWEDIP_SET`, `VEIL_CMD_STATS_GET`,
`VEIL_CMD_XDP_TOKEN_SYNC`. `SESSION_INSTALL` receives already-derived KDF
outputs (tx/rx AEAD keys, nonce prefixes, route-token keys, HP keys,
padding keys, replay window size, policy fields) — never ML-KEM private
state.

## v0 (current prototype) — what actually runs today

The entire data plane (`veil/engine`: peer table, routing table, tag table,
the three hot loops, PMTU, fragmentation, padding, replay) runs as a normal
Go process reading/writing a TUN device
(`veil-linux/tun`, `veil-windows/veiltun`) and a UDP socket — no kernel
module, no Netlink control plane, no XDP. Per-OS clients
(`veil-daemon` on Linux, `veil-client`/`veil-service` on Windows) each embed
the `engine` package directly and call `engine.New()`/`engine.Run()`
in-process; there is no `veild`/`veil.ko` split to speak of yet, and no ABI
boundary between "control brain" and "fast path" — it's one Go binary end to
end per platform.

This is Phase 9 work (`docs/ROADMAP.md`), gated on Phases 2-8 (specs,
vectors, `record/v1`, control frames, PQ, epoch ratchet, fuzzing, and the
`veild` split itself) all landing first. Not started, no ETA.
