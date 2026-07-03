# VEIL Roadmap

**Status:** living document, updated as phases close.
**Last updated:** 2026-07-04 (Go data plane switched to `record/v1`; Phase 2
GUI/mesh milestone-1 retained).
**Scope:** all five repos — `veil` (protocol core), `veil-install`, `veil-linux`,
`veil-windows`, `veil-windows-gui`.

This roadmap turns [`VEIL_FINAL_DEVELOPMENT_SPEC.md`](../../VEIL_FINAL_DEVELOPMENT_SPEC.md)
(the target architecture: `veild` + `veil.ko` + optional XDP, hybrid PQ
handshake, opaque route-token wire format) into tracked phases, reconciled
against what the current Go prototype actually does today. Where the spec's
own phase descriptions are generic, this document adds the concrete file/line
references found by auditing the running code, so nobody has to re-derive
"is this actually true today" from scratch.

The implementation must not move faster than the specs in `docs/spec/`. If
code and spec diverge, the code is wrong until the spec is updated to match a
deliberate decision.

---

## 0. Status snapshot

| Area | State |
|---|---|
| `go build ./...` / `go test ./...` (veil, veil-linux, veil-install) | green |
| `go build`/`go vet` (veil-windows, veil-windows-gui, cross-compiled) | green |
| Phase 1 P0 fixes (§2 below) | **done** — config validation, PSK wired into KDF, fragment range-coverage, engine lifecycle + dynamic AddPeer/RemovePeer, PersistentKeepalive wired in, rate-limited hostile-input logging, DH zero-output abort, secret zeroization |
| Handshake | 2-message WireGuard-Noise-style, Elligator2-encoded ephemerals — **not** the target's TLV/canonical + ML-KEM hybrid scheme |
| Wire record | Go engine uses `record/v1`: `route_token[16] || seq_protected[8] || AEAD`, v1 inner frames, bounded route-token window, RFC-6479 replay commit after AEAD success. `transport/v0` remains as a legacy package/test reference, not the runtime data plane. |
| PQ / kmod / XDP | PQ reference code exists in `pq/` using Go's ML-KEM-768 primitives. kmod/XDP not started; no C/kernel code exists anywhere in any of the 5 repos. |
| Mesh | Phase 2 milestone-1 **done**: `VEIL-MESH-1.md` design doc, `MESH_INTRO` frame, bounded UDP hole-punch, hub relay fallback gated to `Engine.IsHub()`, all unit-tested. Deferred: full ICE/TURN, multi-hop relay, route gossip, the leaf-side "trusted introducer" hardening noted in `VEIL-MESH-1.md` §3.2, and the config-schema question (§9 below, §7 of the doc) |
| GUI | Phase 2 **done**: resizable window, real log streaming (`CmdLogs` + ring buffer), structured Split Tunnel tab with Allowed/Disallowed CIDR editing (client-side subtraction), `config.Serialize()` added to support it. Raw `.conf` editor kept as "Advanced" (§10 below) |

---

## 1. Phase 0 — Baseline and freeze

- Current behavior is the reference point: `go test ./...` passes cleanly in
  `veil` with the Go runtime data plane on `record/v1`. The old
  `transport/v0` package is retained for legacy comparisons/tests, not used
  by `engine` for production records.
- No benchmark harness exists yet in `engine/` beyond the functional test
  suite (`parallel_test.go`, `rekey_test.go`, `padding_test.go`,
  `watchdog_test.go`, `fuzz_test.go`). Adding a dedicated throughput/latency
  benchmark harness is still deferred; add it before any kmod/XDP split so the
  Go and kernel data planes can be compared against the same traffic profile.

## 2. Phase 1 — P0 correctness fixes (done)

These are concrete, file-level fixes to the *current* prototype, not spec-v1
work. Each maps to a real gap found by code audit, not the spec's generic
Section 18 list:

1. **Config validation** — `config/config.go` has zero byte-length validation
   anywhere. A malformed/short/long hex key is silently `copy()`'d into a
   fixed `[32]byte` in `engine.New()`, truncated or zero-padded with no error.
   Bad `AllowedIPs` CIDR entries are silently dropped rather than rejected.
   No duplicate-peer-key rejection (`PeerTable.AddPeer` silently overwrites).
   → Fix: `config.Validate()`.
2. **PSK is decorative** — `core/handshake_machine.go` hardcodes a 32-byte
   zero block as the PSK KDF input in both `ConstructMsg2` and the
   initiator's msg2-processing path; `config.PeerConfig.PresharedKey` is
   parsed but never read anywhere else. → Fix: wire PSK into the real KDF
   chain.
3. **Fragmentation is byte-counted, not range-checked** — `engine/fragment.go`
   sums `len(chunk)` per unique offset in a map; duplicate-offset,
   different-length chunks silently last-write-win with no true interval
   coverage check, and overlapping fragments are accepted. → Fix: interval
   tracking + overlap rejection.
4. **No engine shutdown path** — `Engine.Run(errChan)` launches 3 goroutines
   and returns; there is no `Close()`/`Wait()`/`Shutdown()` anywhere.
   Callers (`veil-windows/wintunnel/tunnel.go`'s `stopLocked()`) close the
   conn/tun first and let engine goroutines error out asynchronously. → Fix:
   `context`-based lifecycle with `Close()`/`Wait()`.
5. **PersistentKeepalive is a dead config field** — parsed in `config.go`,
   round-tripped by `veil-wgimport` and the GUI's raw-conf editor, but
   `engine/session.go`'s `keepaliveInterval()` always uses a fixed jittered
   default regardless. → Fix: wire it in as a per-peer override.
6. **No log rate-limiting on hostile-input paths** — a `log.Printf` per
   malformed handshake/fragment/replay packet is itself a remote log-flood
   vector. **No zeroization** of DH/KDF byte-slice temporaries.

See `docs/spec/VEIL-INVARIANTS-1.md` for the v0-compliance checklist these
fixes are measured against.

## 3. Phase 2 — Specs and test vectors

Write and lock initial drafts (see `docs/spec/`, already scaffolded as part of
this roadmap):

```
VEIL-CANON-1.md       — DRAFT, Go package exists in canon/
VEIL-KDF-1.md         — DRAFT, Go package exists in kdf/; runtime handshake still uses the current core KDF bridge
VEIL-TOKENS-1.md      — DRAFT, Go package exists in tokens/ and powers route tokens in engine/
VEIL-RECORD-1.md      — DRAFT, Go package exists in record/v1 and is used by engine/
VEIL-CONTROL-1.md     — DRAFT, control/v1 package exists; PMTU and MESH_INTRO ride record/v1 control frames
VEIL-PQ-1.md          — DRAFT, pq/ package exists; handshake integration/config gate still pending
VEIL-KMOD-1.md        — DRAFT, not implemented
VEIL-INVARIANTS-1.md  — DRAFT, includes v0-compliance checklist
```

Deterministic test vectors (transcript hash, KDF chain, epoch key outputs,
route token outputs, header protection outputs, record seal/open) are
target-spec (v1) work. Package-level unit vectors exist for the new Go
packages; publish stable cross-language fixture files before starting kmod.

## 4. Phase 3 — Go `record/v1`

Runtime switch done in Go:

- Outer records are now `route_token[16] || seq_protected[8] || AEAD`.
- Header protection, nonce derivation, AEAD associated data, and replay live
  in `record/v1`.
- `engine` uses a bounded receive route-token table/window instead of
  `transport.TagTable`.
- Inner payloads are typed v1 frames (`DATA_IP4`, `DATA_IP6`, `CONTROL`,
  `INNER_FRAGMENT`, `PAD_ONLY`).
- `transport/v0` remains available only as legacy code and a comparison point.

## 5. Phase 4 — Encrypted control frames

Data-plane carrier done: PMTU probe/ack and `MESH_INTRO` are encrypted inside
record/v1 `CONTROL` frames. The `control/v1` TLV capsule helpers exist, but
the daemon/API-level control protocol is still the existing repo-specific
surface.

## 6. Phase 5 — PQ initial hybrid

Reference Go package started in `pq/` with ML-KEM-768 encapsulation,
decapsulation, gate checks, and refresh helpers. Runtime handshake integration
and config/API knobs for strict `PQ_REQUIRED` are still pending.

## 7. Phase 6 — Epoch ratchet and token ladder

Reference Go packages exist in `epoch/` and `tokens/`; route-token derivation
is wired into the Go engine. Full runtime epoch ratchet/refresh policy is still
pending.

## 8. Phase 7 — Fuzzing and invariant tests

Partially started: `engine/fuzz_test.go` now exercises the record/v1 transport
path (route-token lookup, replay, reordering, loss, duplicate rejection, AEAD
failure). Canonical-parser and Netlink fuzzers are kmod-era work, not started.

## 9. Mesh workstream (new — not in the original spec) — milestone-1 done

Today's topology is strictly static point-to-point / hand-configured star
(one config file, static peer list, each peer with a fixed `Endpoint`).
Target: partial mesh — the existing star (hub + static peers) extended with
opportunistic direct P2P between clients, falling back to hub relay when
direct paths aren't reachable (symmetric NAT, etc).

Design doc: `docs/spec/VEIL-MESH-1.md` (done, reviewed). Milestone-1 (done,
in `veil/engine/mesh.go` + `mesh_test.go`):

- `Engine.EnableMeshHub()`/`DisableMeshHub()`/`IsHub()` — runtime hub-role
  flag, off by default, gating all mesh-specific behavior.
- `MESH_INTRO` frame (`VMI1` magic, fixed layout — see doc §3.3): hub tells
  an already-connected client another peer's pubkey, hub-observed endpoint,
  AllowedIPs, and a rendezvous window, riding the existing hub↔client
  session (no new auth mechanism).
- Bounded simultaneous-open UDP hole-punch (5 attempts / 600ms apart / ~3s
  window) reusing the unmodified 2-message handshake; no confirmation within
  the window is an explicit non-failure, not an error.
- Hub relay fallback in `udpToTun`, gated to `IsHub()`: forwards a decrypted
  packet to another connected peer's session instead of writing to local TUN
  when `RoutingTable.Lookup` resolves the destination to a peer other than
  the sender.
- **Security fix during review**: the design doc originally claimed "a hub
  itself ignores an inbound `MESH_INTRO` from one of its clients," but the
  first implementation never actually checked `IsHub()` before processing —
  meaning any authenticated peer could send a crafted `MESH_INTRO`-shaped
  frame and get the receiver to register an arbitrary peer/route and fire
  handshake attempts at an attacker-chosen address (a real SSRF/reflection
  primitive). Fixed by adding the `IsHub()` check inside `handleMeshIntro`
  itself, with a regression test
  (`TestEngine_HubIgnoresInboundMeshIntro`). See `VEIL-MESH-1.md` §3.2 for
  the residual trust-boundary note this surfaced: a leaf still accepts
  `MESH_INTRO` from *any* peer it has a live session with, not only a
  peer it independently trusts as its hub — not currently exploitable since
  nothing calls `sendMeshIntro` yet, but must be closed (a per-peer "trusted
  introducer" marker) before wiring up real hub-triggered introductions.

Explicitly deferred: full ICE/TURN, multi-hop relay, mesh-wide route gossip,
the leaf-side trusted-introducer hardening above, and the config-schema
question below.

## 10. GUI/client workstream (new — not in the original spec) — done

Tracked here because it's product surface, not protocol, but must stay
visibly synchronized with the rest of the project. All landed:

- Visual redesign of the Windows GUI (`veil-windows-gui`): resizable window
  (was fixed 440x680), scrollable content, tightened spacing, same brand
  theme.
- Real logging: `CmdLogs` added to the named-pipe control protocol
  (`veil-windows/control/proto.go`), backed by a 2000-line ring buffer
  (`control/logbuf.go`) that captures the process's existing `log.Printf`
  output via `log.SetOutput`, no engine call-site changes needed. The Logs
  tab polls it on the existing 1500ms cadence.
- Split Tunnel tab: structured per-peer Allowed/Disallowed CIDR editor with
  bulk-import, validated via `config.PeerConfig.Validate()`. "Disallowed" is
  a pure GUI-side concept (client-side CIDR subtraction at Connect time,
  stored in a `<name>.disallowed.json` sidecar) — never added to
  `config.PeerConfig` or the wire protocol. Required `config.Serialize()`
  (new INI writer in `veil/config/config.go`, the inverse of
  `LoadConfigString`), which any other caller can now reuse.
- Raw `.conf` editor kept as "Advanced", unchanged, still the on-disk source
  of truth.

## 11. Phases 8-11 — `veild` split, `veil.ko` MVP, XDP prefilter, throughput

Not started, no ETA. The Go data plane is now on the target record format,
but kmod/XDP still need stable fixture vectors, the runtime PQ gate, and the
epoch refresh policy finalized first. No C/kernel code exists in any of the 5
repos today.

---

## 12. Cross-repo sync matrix

Any change in `veil` that alters config/wire/engine-API surface is not "done"
until the affected downstream repos build green against it. This table is
the authoritative list of what moves together.

| `veil` change | Breaking? | veil-linux | veil-windows | veil-windows-gui | veil-install |
|---|---|---|---|---|---|
| `config.Validate()` added, called from `LoadConfig`/`LoadConfigString` | Yes (bad configs that previously loaded silently now error) | no code change needed (already just calls `LoadConfig`) | no code change needed | no code change needed (config text validated service-side at `connect`) | yes — `veil-wgimport` and `veil-config` should call `Validate()` explicitly to surface errors before write |
| PSK wired into real KDF | Yes (configs with PSK set now handshake differently; PSK-less configs unaffected) | none | none | none | none |
| `Engine.Run(ctx, errChan)` signature change + `Close()`/`Wait()` | Yes | `cmd/veil-daemon/main.go` call site + shutdown path | `cmd/veil-client/main.go` call site + shutdown path; `wintunnel/tunnel.go` `Connect`/`stopLocked` | none (doesn't call Engine directly) | none |
| `Engine.AddPeer`/`RemovePeer` runtime API added | No (additive) | none required yet | none required yet | none required yet (consumed later by mesh work) | none |
| Fragmentation range-coverage fix | No (stricter acceptance; now carried as record/v1 `INNER_FRAGMENT`) | none | none | none | none |
| `PersistentKeepalive` wired in | No (same config field, now honored) | none | none | none | none |
| Go data plane switched to `record/v1` | Yes (wire-format change) | bump `github.com/veil-proto/veil` and rebuild daemon | bump `github.com/veil-proto/veil` and rebuild client/service | bump `veil`/`veil-windows` module pins and rebuild GUI/service | bump `github.com/veil-proto/veil`; tooling must emit configs compatible with the new runtime |
| `config.Serialize()` writer added | No (additive) | none required | none required | consumed by the Split Tunnel tab (done) | optional future use |
| `CmdLogs` control-protocol command + `LogBuffer` | No (additive) | n/a (Linux daemon has no GUI/control pipe) | `control/{proto,client,server}.go`, `wintunnel/tunnel.go` (`Logs` on `Handler`) | `cmd/veil-service/handler_windows.go` wires the ring buffer; GUI Logs tab consumes it | none |
| `MESH_INTRO` frame + `Engine.IsHub()`/hub relay | No (additive, opt-in via `EnableMeshHub()`) | none required yet — no daemon call site enables hub mode | none required yet | none required yet | none |
| Mesh config-schema marker ("this peer is my hub") | Not yet landed — deferred, see §9 | will need it once a daemon flag/config toggles hub mode | same | same (a "hub" toggle in the GUI) | install tooling would need to emit hub configs |

---

## 13. Immediate next steps

1. Sync all downstream repos to the new `github.com/veil-proto/veil@main`
   pseudo-version and keep the cross-repo test/build matrix green.
2. Publish stable v1 fixture files for canon/KDF/tokens/record/control/PQ so
   Go, future C/kmod, and any Rust test harness all prove byte-for-byte
   compatibility before kernel work starts.
3. Wire the runtime PQ gate and epoch refresh policy into the Go handshake.
4. Start the `veild`/`veil.ko` split only after the Go runtime remains green on
   the target data-plane format.
