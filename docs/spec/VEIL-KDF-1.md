# VEIL-KDF-1

**Status:** DRAFT (target/v1). See §v0 Appendix below for what actually runs
today — they are materially different schemes; do not conflate them.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` §7.

## Target (v1) scheme

Default KDF: `HKDF-SHA256`. Domain separation via fixed, never-transmitted
labels (`proto_id`, `record_id`, `control_id`, `kdf_id`). Transcript hash
chains `TH0..THF..TH_CONF` over every negotiation field (`suite_id`,
`pq_policy_id`, AEAD choice, header protection mode, padding profile, token
policy, fragmentation policy, ephemeral public keys, ML-KEM material hashes,
identity/auth mode, config fingerprint, deployment ID). Every KDF input is
typed (`secret_type`, `status: disabled|present`, `length`, `value`) — an
absent optional secret is mixed as a typed *disabled* input, never an
ambiguous all-zero block. DH terms: `dh_ee`, `dh_es`, `dh_se` (client-static
auth only), `dh_ss` (optional). An enabled term returning all-zero output
aborts; a disabled term is a typed disabled input, never silently zeroed.
`MixKey`/`Expand` follow standard HKDF-Extract/Expand. Key confirmation
(`confirm_mac_c2s`/`confirm_mac_s2c`) proves both sides hold
`handshake_secret` without circular dependency; `master_secret` → `session_root`
→ `epoch_root_0` follow. See the target spec §7 for the full 8-step chaining
key derivation (`ck0..ck8`).

## v0 (current prototype) — what actually runs today

The current Go handshake (`core/handshake_machine.go`, `core/crypto.go`) is
an entirely different, simpler scheme: **HKDF-BLAKE2s**, no `suite_id`, no
typed KDF inputs, no PQ term.

- KDF primitive: `HKDF-BLAKE2s` (`core/handshake.go`'s `HKDFBlake2s`, wrapping
  `golang.org/x/crypto/hkdf` with a BLAKE2s-256 hash).
- Two-message handshake (`ConstructMsg1/ProcessMsg1`,
  `ConstructMsg2/ProcessMsg2`), ephemeral keys carried as Elligator2
  representatives (`core/elligator.go`) rather than raw X25519 points.
- Pre-DH gate: `mac1`, a BLAKE2s-MAC keyed by `K_mac1 = BLAKE2s(key=K_net,
  data=NID||label||S_pub)` (`DeriveMac1Key`/`CalculateMac1` in `crypto.go`),
  verified over the wire image *before* any DH or decode — this is the
  closest v0 analog to `suite_id`/policy binding, though it only binds
  `K_net`+`NID`, not a full negotiated suite.
- Transcript: a single running BLAKE2s chain `Th` (`hm.Th`), updated after
  msg1 (`th1`) and msg2 (`th2`), analogous in spirit to the target's
  `TH0..THF` chain but much shorter and not typed-field-aware.
- Chaining key schedule (`computeTransportKeys` in `handshake_machine.go`):

  ```text
  kHs1    = HKDF-BLAKE2s(dh_es, salt=salt1, info="VEIL hs1 key")       // encrypts msg1 payload
  kHs2Input = dh_ee || dh_se || dh_static || psk_input(32 bytes)
  kHs2    = HKDF-BLAKE2s(kHs2Input, salt=Th, info="VEIL hs2 key")      // encrypts msg2 payload
  kMasterInput = dh_es || kHs2Input
  kMaster = HKDF-BLAKE2s(kMasterInput, salt=Th, info="VEIL session master")
  kI2R    = HKDF-BLAKE2s(kMaster, salt=Th, info="transport i2r key")
  kR2I    = HKDF-BLAKE2s(kMaster, salt=Th, info="transport r2i key")
  kTagI2R = HKDF-BLAKE2s(kMaster, salt=Th, info="tag i2r key")
  kTagR2I = HKDF-BLAKE2s(kMaster, salt=Th, info="tag r2i key")
  ```

- `psk_input`: as of the Phase 1 P0 fix (`docs/ROADMAP.md` §2), this is the
  actual 32-byte configured `PresharedKey` when present, or a 32-byte zero
  block when absent (`HandshakeMachine.pskInput()` in `handshake_machine.go`).
  Before that fix it was *always* a hardcoded zero block regardless of
  configuration — this doc's job is to make sure that distinction is never
  lost again. There is no typed disabled/present marker (target invariant
  §14) — presence is inferred only from whether the derived keys differ, not
  from an explicit typed field. Closing that gap is v1/Phase-2-3 work, not
  part of the P0 fix.
- DH all-zero-output check: as of the Phase 1 P0 fix, every enabled DH term
  (`dh_es` in both msg1 paths, `dh_ee`/`dh_se`/`dh_static` in both msg2
  paths) aborts the handshake if the X25519 output is all-zero
  (`isAllZero` in `handshake_machine.go`), matching target invariant §13.
- No suite negotiation exists at all — the crypto suite
  (`X25519-BLAKE2s-ChaCha20Poly1305`, `core.CryptoSuite`) is a compile-time
  constant baked into `DeriveNID`, not a negotiated/transcript-bound field.
