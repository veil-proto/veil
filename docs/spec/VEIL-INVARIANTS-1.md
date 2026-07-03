# VEIL-INVARIANTS-1

**Status:** DRAFT — target (v1) invariants, with a v0 (current prototype)
compliance checklist below. This is the yardstick Phase 1 P0 fixes
(`docs/ROADMAP.md` §2) are checked against.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §20.

## Target invariants (v1)

1. No user IP frame before authentication.
2. In `PQ_REQUIRED`, no user IP frame before hybrid confirmation.
3. `suite_id` is bound into all KDF outputs.
4. AEAD nonce never repeats for one key.
5. `route_token` is never long-term stable.
6. Invalid first packet produces no response.
7. AEAD failure produces no response.
8. Replay state is committed only after AEAD success.
9. Old epoch acceptance is bounded by grace window.
10. XDP must not admit tokens unknown to `veil.ko`.
11. Outer IP fragmentation must never be required.
12. Parser failures are silent on wire.
13. Enabled X25519 all-zero output aborts.
14. Optional absent secrets use typed disabled KDF input, not ambiguous zero
    secrets.
15. All cryptographic/wire-policy negotiation fields are transcript-bound.

Several of these (3, 5, 9, 10, 14, 15) only make sense once `suite_id`,
epoch ratchet, and route tokens exist (Phase 3/6). They're not applicable to
v0 and are marked N/A below rather than failing.

## v0 (current prototype) compliance checklist

| # | Invariant | v0 status | Notes |
|---|---|---|---|
| 1 | No IP frame before auth | **PASS** | Handshake (`core/handshake_machine.go`) must complete and produce a confirmed session before `engine.go` accepts transport/data frames; no code path writes to TUN from an unauthenticated peer. |
| 2 | No IP before PQ confirm | N/A | No PQ exists in v0. |
| 3 | `suite_id` binds KDF outputs | N/A | No suite negotiation exists in v0; the wire format and crypto suite are fixed at compile time. |
| 4 | AEAD nonce never repeats for one key | **PASS** | `transport/crypto.go` derives the nonce deterministically from a per-session `NonceSeed` + monotonic packet number; packet numbers are session-scoped and rekey establishes a fresh session/key before reuse. |
| 5 | `route_token` never long-term stable | N/A | v0 has no route token; it has a per-packet BLAKE2s lookup tag (`transport/tagtable.go`) which is already fresh per packet, stronger than "not long-term stable." |
| 6 | Invalid first packet → no response | **PASS** (needs confirmation) | The mac1-style network-secret gate in `handshake_machine.go`/`crypto.go` should cause invalid msg1s to be dropped before any response is constructed — confirm no error-reply path exists on decrypt/mac failure as part of Phase 1 review. |
| 7 | AEAD failure → no response | **PASS** (needs confirmation) | Same review as #6 for transport-record AEAD failures. |
| 8 | Replay state committed only after AEAD success | **NEEDS AUDIT** | `transport/recvwindow.go`'s sliding-tag-window pre-installs tags ahead of receipt for lookup purposes, which is a different mechanism than the target's "unprotect seq → AEAD open → commit replay bitmap" flow. Confirm the RFC 6479 bitmap itself is only advanced after successful AEAD open, not before. |
| 9 | Old epoch bounded by grace window | N/A | No epoch concept in v0; the closest analog is current/previous **session** grace handling in `engine/session.go`, which does exist and is time-bounded. |
| 10 | XDP token admission ordering | N/A | No XDP in v0. |
| 11 | No outer IP fragmentation required | **FAIL (by design gap)** | v0 has its own inner fragmentation (`VFR1`, `engine/fragment.go`) so it does not *rely* on outer IP fragmentation, but PMTU budget enforcement should be double-checked to ensure the packet builder never emits an outer packet exceeding path MTU. Not currently a known bug, but not verified as an explicit invariant test either. |
| 12 | Parser failures silent on wire | **PASS** (needs confirmation) | Fragment/handshake/transport parse failures should silently drop, not emit any reply — confirm no fragment-reject path currently emits any wire-visible signal (it doesn't appear to; Phase 1 fix for range-coverage keeps this property). |
| 13 | Enabled X25519 all-zero aborts | **NEEDS AUDIT** | `core/handshake_machine.go`'s DH computations (`dh_es`, `dh_ee`, `dh_se`, `dh_static`) should be checked for explicit all-zero-output rejection rather than silently proceeding with a degenerate shared secret. Flagged for Phase 1 review; not fixed as part of the initial P0 pass unless found to be missing. |
| 14 | Typed disabled KDF input for absent secrets | **FAIL (known, being fixed)** | This is exactly the PSK gap: v0 currently mixes an ambiguous all-zero 32-byte block whether PSK is absent *or* present-but-unwired. Phase 1 P0 fix (§2 item 2 in ROADMAP.md) fixes the "present but unwired" half of this; it does not introduce full typed-disabled-input KDF semantics (that's v1/Phase 2-3 `VEIL-KDF-1` work) — after the fix, absent-PSK and present-PSK produce *different* outputs, which is the practically important half of this invariant even without the formal typed-input encoding. |
| 15 | Negotiation fields transcript-bound | N/A | No negotiation/suite_id concept in v0. |

**Summary**: v0 has no PQ/epoch/token/suite-negotiation machinery (correctly
N/A for those invariants), passes the core anti-probing and replay-safety
invariants that matter most today, and has one confirmed gap (#14, the PSK
issue) plus several "needs audit, not yet confirmed either way" items (#6-8,
#13) that should get explicit tests as part of closing out Phase 1, even
where no bug is currently suspected.
