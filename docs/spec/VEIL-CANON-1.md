# VEIL-CANON-1

**Status:** DRAFT (target/v1). **NOT IMPLEMENTED** — no TLV/canonical encoder
exists anywhere in the codebase today.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §5.

## Target (v1) scheme

Deterministic TLV encoding for all transcript-bearing messages:
`field_id:u16-BE, length:u32-BE, value:length bytes`, fields sorted ascending
by `field_id`, duplicate `field_id` invalid, unknown critical fields abort,
unknown non-critical fields may be skipped only if their bytes remain
included in transcript hashing, maps never serialized in language runtime
order. Capsules: `capsule_type:u16, capsule_version:u16, field_count:u32,
fields...`. Exists so Go, C, Rust, and kernel-side tests produce identical
transcript hashes.

## v0 (current prototype) — what actually runs today

v0 has no general-purpose canonical encoder. Every wire structure
(`Msg1Payload`, `Msg2SessionParams` in `core/handshake.go`/`handshake2.go`)
is a hand-packed, fixed-layout byte struct with hardcoded field offsets and
a fixed total size (`Encode()`/`Decode...()` methods doing manual
`copy()`/`binary.*Endian` calls at fixed positions) — there is no field-ID
tagging, no sorting requirement, no critical/non-critical field distinction,
and no concept of skippable unknown fields. This is simpler and has less
negotiation flexibility than the target's TLV scheme by design: v0's fields
are compile-time fixed, not negotiated, so there has been nothing to encode
generically yet.

Adopting `VEIL-CANON-1` is prerequisite work for `record/v1` (Phase 3) and
the PQ hybrid handshake (Phase 5), since both need to carry variable-length,
possibly-extensible negotiation data (ML-KEM public keys/ciphertexts, suite
IDs, policy fields) that a fixed-offset struct can't accommodate cleanly.
Not started.
