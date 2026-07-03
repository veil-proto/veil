# VEIL-RECORD-1

**Status:** DRAFT (target/v1). See §v0 Appendix — today's wire format is a
different, simpler scheme.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §11-12, §14.

## Target (v1) scheme

Outer UDP record: `route_token[16] || seq_protected[8] || AEAD
ciphertext+tag`. No clear version, magic, message type, peer ID, or plaintext
counter. Sequence header protection is QUIC-style (sample the ciphertext,
derive an 8-byte mask from a suite-specific `HP()` function, XOR it over the
plaintext sequence) — a constant XOR mask is explicitly forbidden because it
leaks monotonic-counter patterns. Replay state commits only after AEAD
success. No outer IP fragmentation is ever required (IPv6 baseline MTU
1280); oversized packets use `INNER_FRAGMENT` (range-based reassembly,
overlap rejection, per-peer buffer/byte/TTL limits) instead. Inner frame
grammar: `frame_type:u8, flags:u8, body_len:u16, body, padding, pad_len:u16`,
with `DATA_IP4/DATA_IP6/CONTROL/PAD_ONLY/INNER_FRAGMENT` as the initial frame
types (`0x01`-`0x05`).

## v0 (current prototype) — what actually runs today

Wire format (`transport/crypto.go`) is not token+header-protection based at
all — it's a cleartext pseudorandom lookup tag plus AEAD:

```text
wire = tag[16, cleartext] || AEAD_ciphertext+tag
```

- `tag`: a fresh, unlinkable per-packet BLAKE2s digest (`DeriveTag`/
  `deriveTagInto`) used purely as a receiver-side session lookup key via
  `transport/tagtable.go`'s `TagTable` — not a stable per-session identifier
  like WireGuard's 4-byte receiver index, but also not header-protected like
  the target's `route_token`. It's cleartext by design (the tag itself is
  meant to look random to a passive observer, not to be hidden behind header
  protection), which is a real difference from the target's threat model —
  the target additionally hides *that a route token even changed* behind
  header protection framing; v0 doesn't need to, since the tag is fresh
  every packet.
- Nonce: deterministic, derived from a per-session `NonceSeed` (established
  during handshake) plus a monotonic packet number — not random, and not
  itself protected on the wire the way the target's `seq_protected` is (v0
  has no visible sequence field at all; the packet number is implicit,
  recovered by the receiver via the replay window / tag table rather than
  read off the wire).
- No header protection layer exists — nothing analogous to `HP()` in v0.
  This is not currently believed to be a security gap (v0 has no visible
  sequence field to protect in the first place), but it means v0 cannot
  claim the specific "header-protected sequence" property the target
  requires; that property doesn't yet exist here.
- Replay: RFC 6479-style 8192-bit sliding bitmap (`transport/recvwindow.go`),
  plus a "sliding tag window" that pre-installs tags for a bounded lookahead
  range into `TagTable`. Per Phase 1 P0 review (see `VEIL-INVARIANTS-1.md`
  item 8), the bitmap itself should only advance after AEAD success —
  flagged for audit, not a known bug.
- Fragmentation: custom `VFR1` magic-tagged inner fragments
  (`engine/fragment.go`), fixed prior to this doc's writing (Phase 1 P0) to
  use true interval-coverage tracking and reject overlapping fragments,
  matching the target's §14.2 rules even though the wire format itself
  (`VFR1` framing) predates and differs from the target's `INNER_FRAGMENT`
  frame-type-based grammar.
- No general inner frame-type byte exists — v0 distinguishes "VFR1-tagged
  fragment" from "raw IP packet" by magic-prefix sniffing in the decap path,
  not by a `frame_type` field. Adopting the target's typed frame grammar is
  Phase 3/4 (`record/v1` + control frames) work.
