# VEIL-RECORD-1

**Status:** DRAFT, implemented in the Go runtime data plane.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` sections 11, 12, and 14.

## Wire Record

Outer UDP record:

```text
route_token[16] || seq_protected[8] || AEAD(ciphertext || tag)
```

There is no clear version, magic, message type, peer ID, or plaintext counter.
The receiver uses `route_token` for bounded session lookup, unprotects the
sequence from the ciphertext sample, opens AEAD with the plaintext sequence in
associated data, and commits replay state only after AEAD succeeds.

Implemented in:

- `record/v1/record.go`: seal/open, header protection, nonce/ad construction.
- `record/v1/replay.go`: RFC-6479-style replay bitmap.
- `record/v1/frame.go`: typed inner frames and padding grammar.
- `engine/route_tokens.go`: bounded receive token table/window.
- `engine/fragment.go`: v1 `INNER_FRAGMENT` body grammar and reassembly.

## Inner Frames

Inner plaintext is a typed frame:

```text
frame_type:u8 || flags:u8 || body_len:u16 || body || padding || pad_len:u16
```

Initial frame types:

- `DATA_IP4`
- `DATA_IP6`
- `CONTROL`
- `PAD_ONLY`
- `INNER_FRAGMENT`

Oversized packets never require outer IP fragmentation. The Go engine splits
them into `INNER_FRAGMENT` frames with range-based reassembly, overlap
rejection, per-session buffer limits, and TTL cleanup.

## Legacy Note

The old `transport` package remains in the repository as `transport/v0`-era
code for comparison and compatibility tests. It is no longer the production
record format used by `engine`.
