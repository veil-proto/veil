# VEIL-CANON-1

**Status:** DRAFT. Go implementation exists in `canon/`; stable fixture files
for other implementations are still pending.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` section 5.

## Scheme

Deterministic TLV encoding for transcript-bearing messages:

```text
field_id:u16-BE || length:u32-BE || value
```

Fields are sorted by `field_id`; duplicate field IDs are invalid. Unknown
critical fields abort. Unknown non-critical fields may be skipped only while
their bytes remain included in transcript hashing. Maps are never serialized in
language runtime order.

Capsule header:

```text
capsule_type:u16 || capsule_version:u16 || field_count:u32 || fields...
```

## Go Runtime State

`canon/` provides the deterministic field/capsule encoder and parser used by
the v1 helper packages and tests. Before kmod work starts, publish stable
cross-language fixtures so the future C implementation can prove byte-for-byte
compatibility with Go.
