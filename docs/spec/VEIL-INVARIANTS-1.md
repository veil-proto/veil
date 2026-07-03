# VEIL-INVARIANTS-1

**Status:** DRAFT. This checklist tracks the Go runtime after the record/v1
data-plane switch.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` section 20.

## Invariants

| # | Invariant | Go runtime status | Notes |
|---|---|---|---|
| 1 | No user IP frame before authentication | PASS | `engine` installs a session only after the handshake produces transport keys. |
| 2 | In `PQ_REQUIRED`, no user IP frame before hybrid confirmation | PENDING | PQ helpers exist in `pq/`; runtime PQ policy/gate is not wired yet. |
| 3 | `suite_id` is bound into all KDF outputs | PARTIAL | `kdf/` has typed suite inputs; runtime handshake still uses the current `core` bridge. |
| 4 | AEAD nonce never repeats for one key | PASS | record/v1 nonce prefix plus per-session monotonic sequence. |
| 5 | `route_token` is never long-term stable | PASS | `engine` derives route tokens per token slot and direction, with bounded receive windows. |
| 6 | Invalid first packet produces no response | PASS | Invalid handshake packets are silently dropped. |
| 7 | AEAD failure produces no response | PASS | `record/v1.Open` errors are dropped; no response is emitted. |
| 8 | Replay state is committed only after AEAD success | PASS | `record/v1.Open` pre-checks the sequence, opens AEAD, then commits replay. |
| 9 | Old epoch/session acceptance is bounded by grace window | PASS for sessions | Current/previous session grace is time-bounded by `rejectAfterTime`; full epoch ratchet policy is pending. |
| 10 | XDP must not admit tokens unknown to `veil.ko` | N/A | No XDP/kmod exists yet. |
| 11 | Outer IP fragmentation must never be required | PASS | record/v1 payload budget and `INNER_FRAGMENT` splitting keep UDP payloads inside the configured budget. |
| 12 | Parser failures are silent on wire | PASS | Bad record, frame, control, and fragment parses are drops. |
| 13 | Enabled X25519 all-zero output aborts | PASS | `core` rejects all-zero DH outputs. |
| 14 | Optional absent secrets use typed disabled KDF input | PARTIAL | `kdf/` supports typed inputs; runtime PSK bridge still preserves legacy compatibility. |
| 15 | Cryptographic/wire-policy negotiation fields are transcript-bound | PARTIAL | Reference packages exist; full runtime negotiation/PQ policy binding is pending. |

## Next Runtime Gaps

Before kmod starts, close the remaining non-kernel runtime gaps:

- wire the PQ policy gate and hybrid confirmation into the Go handshake;
- finalize the epoch refresh policy;
- publish stable fixture files for canon/KDF/tokens/record/control/PQ;
- keep downstream clients green against the target Go data plane.
