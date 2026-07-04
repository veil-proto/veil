package core

import (
	"crypto/subtle"
	"errors"

	"github.com/veil-proto/veil/transport"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type HandshakeMachine struct {
	IsInitiator bool
	KNet        []byte
	NID         []byte
	LocalPriv   [32]byte
	LocalPub    [32]byte
	RemotePub   [32]byte

	// PSK is the optional 32-byte per-peer pre-shared secret, mixed into the
	// msg2/session KDF as an additional authentication factor. Nil/empty means
	// no PSK is configured for this peer: the KDF input falls back to a fixed
	// 32-byte zero block, byte-identical to how every handshake behaved before
	// PSK support existed, so PSK-less configs are unaffected by this field.
	// Responders learn which peer they're talking to only after ProcessMsg1
	// (which sets RemotePub from the decrypted payload), so callers on the
	// responder side must set PSK between ProcessMsg1 and ConstructMsg2.
	PSK []byte

	LocalEPriv [32]byte
	LocalEPub  [32]byte
	LocalERep  [32]byte // Elligator2 representative of LocalEPub (wire image)
	RemoteEPub [32]byte
	RemoteERep [32]byte // Elligator2 representative received from the peer

	Th   []byte
	DhEs []byte // X25519(e_i_priv, S_pub)
}

// ZeroSecrets overwrites this handshake's remaining per-object secret state
// once the machine is no longer needed (handshake complete, superseded by a
// new attempt, or abandoned) — see callers in engine/peer.go's Promote and
// SetPending.
//
// P0.5 (VEIL-Combined-Roadmap.md) originally proposed also zeroing hm.KNet
// and hm.PSK here, but both are *shared references*, not per-handshake
// copies: hm.KNet is engine.go's e.cfg.Interface.NetSecret handed to every
// HandshakeMachine constructed for the life of the Engine
// (core.NewHandshakeMachine(..., e.cfg.Interface.NetSecret, ...)), and
// hm.PSK is set directly from peer.presharedKey (engine.go:
// `rhm.PSK = peer.presharedKey`), the Peer's own long-lived config state.
// Zeroing either in place would corrupt every future handshake for this
// Engine/Peer, not just this one — so only LocalEPriv (a genuine one-off
// ephemeral private key, never referenced anywhere else) is zeroed here.
// DhEs is already zeroed inside computeTransportKeys once a handshake
// completes; this covers the case where a machine never gets that far
// (abandoned/superseded pending attempt).
func (hm *HandshakeMachine) ZeroSecrets() {
	zeroBytes(hm.LocalEPriv[:])
	zeroBytes(hm.DhEs)
}

// zeroBytes overwrites b in place. Best-effort hygiene for short-lived secret
// buffers (DH outputs, KDF inputs) once they've been consumed; Go's GC and
// compiler make no hard guarantees against this being optimized away or the
// backing memory being copied elsewhere first, but it costs nothing and
// narrows the window a secret sits in memory after last use.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// isAllZero reports whether every byte in b is zero. X25519 outputs an
// all-zero shared secret only for a small set of degenerate/low-order public
// keys; a correctly random peer key essentially never produces one, so
// seeing it here means the remote key was crafted to force a known,
// attacker-predictable shared secret. Every DH term VEIL enables must be
// checked with this and abort the handshake on a match — silently proceeding
// would hand the attacker a known session key.
func isAllZero(b []byte) bool {
	var v byte
	for _, c := range b {
		v |= c
	}
	return v == 0
}

// pskInput returns the 32-byte PSK KDF input for this handshake: the
// configured PSK if present and correctly sized, otherwise a fixed zero
// block (the historical always-zero behavior, preserved for PSK-less peers).
func (hm *HandshakeMachine) pskInput() []byte {
	if len(hm.PSK) == 32 {
		out := make([]byte, 32)
		copy(out, hm.PSK)
		return out
	}
	return make([]byte, 32)
}

func NewHandshakeMachine(isInitiator bool, kNet, nid []byte, localPriv, remotePub [32]byte) *HandshakeMachine {
	hm := &HandshakeMachine{
		IsInitiator: isInitiator,
		KNet:        kNet,
		NID:         nid,
		LocalPriv:   localPriv,
		RemotePub:   remotePub,
	}
	curve25519.ScalarBaseMult(&hm.LocalPub, &hm.LocalPriv)
	return hm
}

// Msg1 wire layout (P0.6, VEIL-Combined-Roadmap.md: the previous 0-16-byte
// random prefix is removed — padHandshake's length-bucket padding already
// obscures message size without it, so the prefix bought no additional wire-
// image variance for 5x the MAC1 verification cost on every inbound Msg1):
//
//	e_i_rep    [32]  Elligator2 representative of the ephemeral public key
//	enc_static [48]  AEAD(k1, Msg1StaticPayload) — 32-byte payload + 16-byte tag
//	enc_auth   [68]  AEAD(k2, Msg1AuthPayload)   — 52-byte payload + 16-byte tag
//	mac1       [16]
const (
	msg1ERepLen     = 32
	msg1StaticCTLen = 32 + 16
	msg1AuthCTLen   = 52 + 16
	msg1Mac1Len     = 16
	msg1TotalLen    = msg1ERepLen + msg1StaticCTLen + msg1AuthCTLen + msg1Mac1Len
)

// ConstructMsg1 builds Msg1 as two separately-keyed AEAD payloads (P0.3,
// VEIL-Combined-Roadmap.md): see ProcessMsg1's doc comment for the attack
// this closes and why the two stages must stay separate.
func (hm *HandshakeMachine) ConstructMsg1() ([]byte, error) {
	if !hm.IsInitiator {
		return nil, errors.New("only initiator can construct msg1")
	}

	var err error
	hm.LocalEPriv, hm.LocalERep, err = GenerateElligatorKeypair()
	if err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(hm.LocalEPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(hm.LocalEPub[:], pub)

	hm.DhEs, err = curve25519.X25519(hm.LocalEPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, err
	}
	if isAllZero(hm.DhEs) {
		return nil, errors.New("dh_es produced an all-zero shared secret")
	}

	dhSs, err := curve25519.X25519(hm.LocalPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, err
	}
	if isAllZero(dhSs) {
		return nil, errors.New("dh_ss produced an all-zero shared secret")
	}

	// Stage 1: encrypt the claimed static public key under k1, which only
	// requires dh_es = DH(e_i, S_r) — an ephemeral-static term computable by
	// anyone who knows the responder's public key (no secret of this
	// initiator's is needed). This stage alone proves nothing about identity;
	// see ProcessMsg1.
	h1, _ := blake2s.New256(nil)
	h1.Write(hm.KNet)
	h1.Write(hm.NID)
	h1.Write([]byte("salt/msg1static"))
	h1.Write(hm.RemotePub[:])
	h1.Write(hm.LocalEPub[:])
	salt1 := h1.Sum(nil)
	k1, err := HKDFBlake2s(hm.DhEs, salt1, []byte("VEIL hs1 static key"), 32)
	if err != nil {
		return nil, err
	}

	hNonce1, _ := blake2s.New256(k1)
	hNonce1.Write([]byte("nonce/msg1static"))
	hNonce1.Write(hm.LocalEPub[:])
	hNonce1.Write(hm.RemotePub[:])
	nonce1 := hNonce1.Sum(nil)[:12]

	var ad1 []byte
	ad1 = append(ad1, hm.NID...)
	ad1 = append(ad1, hm.RemotePub[:]...)
	ad1 = append(ad1, hm.LocalEPub[:]...)

	var staticPayload Msg1StaticPayload
	copy(staticPayload.CPub[:], hm.LocalPub[:])

	aead1, err := chacha20poly1305.New(k1)
	if err != nil {
		return nil, err
	}
	encStatic := aead1.Seal(nil, nonce1, staticPayload.Encode(), ad1)
	zeroBytes(k1)

	// Stage 2: encrypt timestamp/params under k2, which requires dh_ss =
	// DH(S_i, S_r) — provable only by whoever holds the static private key
	// matching the CPub just sealed into encStatic. Binding ad2 to encStatic
	// ties the two stages together so they can't be recombined from
	// different Msg1s.
	h2, _ := blake2s.New256(nil)
	h2.Write(hm.KNet)
	h2.Write(hm.NID)
	h2.Write([]byte("salt/msg1auth"))
	h2.Write(hm.RemotePub[:])
	h2.Write(hm.LocalEPub[:])
	h2.Write(hm.LocalPub[:])
	salt2 := h2.Sum(nil)
	k2, err := HKDFBlake2s(dhSs, salt2, []byte("VEIL hs1 auth key"), 32)
	zeroBytes(dhSs)
	if err != nil {
		return nil, err
	}

	hNonce2, _ := blake2s.New256(k2)
	hNonce2.Write([]byte("nonce/msg1auth"))
	hNonce2.Write(hm.LocalEPub[:])
	hNonce2.Write(hm.RemotePub[:])
	hNonce2.Write(hm.LocalPub[:])
	nonce2 := hNonce2.Sum(nil)[:12]

	var ad2 []byte
	ad2 = append(ad2, hm.NID...)
	ad2 = append(ad2, hm.RemotePub[:]...)
	ad2 = append(ad2, hm.LocalEPub[:]...)
	ad2 = append(ad2, encStatic...)

	var authPayload Msg1AuthPayload
	authPayload.Timestamp = EncodeMonotonicTimestamp()
	authPayload.RequestedTagLen = 16

	aead2, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, err
	}
	encAuth := aead2.Seal(nil, nonce2, authPayload.Encode(), ad2)
	zeroBytes(k2)

	kMac1I2r, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/i2r", hm.RemotePub[:])
	if err != nil {
		return nil, err
	}

	// MAC1 and the transcript bind the exact wire image (Elligator2
	// representative) plus both ciphertexts, so the responder can verify
	// MAC1 — the pre-DH anti-probing gate — before decoding the
	// representative into a curve point or doing any DH work at all.
	hMac, _ := blake2s.New256(kMac1I2r)
	hMac.Write(hm.LocalERep[:])
	hMac.Write(encStatic)
	hMac.Write(encAuth)
	mac1 := hMac.Sum(nil)[:16]

	var packet []byte
	packet = append(packet, hm.LocalERep[:]...)
	packet = append(packet, encStatic...)
	packet = append(packet, encAuth...)
	packet = append(packet, mac1...)

	// Transcript
	hTh1, _ := blake2s.New256(nil)
	hTh1.Write(hm.NID)
	hTh1.Write([]byte("th1"))
	hTh1.Write(hm.LocalERep[:])
	hTh1.Write(encStatic)
	hTh1.Write(encAuth)
	hTh1.Write(mac1)
	hm.Th = hTh1.Sum(nil)

	return packet, nil
}

// ProcessMsg1 verifies and decodes an inbound Msg1, returning the
// (now-trustworthy) auth payload the caller may act on.
//
// P0.3 (VEIL-Combined-Roadmap.md): the previous single-ciphertext Msg1 format
// encrypted CPub and Timestamp together under a key (kHs1 = HKDF(DH(e_i,
// S_r))) that requires no secret belonging to the claimed initiator — e_i is
// attacker-chosen and S_r is public knowledge to any K_net-holding network
// member. An attacker could therefore forge a Msg1 claiming an arbitrary
// victim's CPub with an advanced timestamp, and the responder would decrypt
// it, look up the real victim Peer, and call
// Peer.CheckAndUpdateMsg1Timestamp — permanently advancing the victim's
// timestamp high-water mark (a strictly-increasing anti-replay counter) and
// so silently jamming every subsequent legitimate Msg1 from that victim, a
// standing DoS the victim cannot detect or recover from without a config
// change. The attacker never needed the victim's static private key at all.
//
// The fix splits Msg1 into two independently-keyed AEAD stages: stage 1
// (encStatic) decrypts under k1 = HKDF(DH(e_i, S_r)) exactly as before and
// yields only the claimed CPub — still unauthenticated, not committed to
// hm.RemotePub yet, and the caller must not use it to look up or mutate any
// Peer state. Stage 2 (encAuth) decrypts under k2 = HKDF(DH(S_i, S_r)),
// which requires the static private key matching the CPub claimed in stage
// 1 (X25519 is symmetric: only the real S_i or this responder's own S_r
// could have computed it). Only once stage 2's AEAD.Open succeeds — proving
// the sender really holds S_i's private key — does this function commit
// claimedPub to hm.RemotePub and return the auth payload at all. Every
// caller (engine.go's handleHandshake) therefore cannot reach
// CheckAndUpdateMsg1Timestamp, SetPath, or any other peer-state mutation
// without that proof already having succeeded.
func (hm *HandshakeMachine) ProcessMsg1(packet []byte) (*Msg1AuthPayload, error) {
	if hm.IsInitiator {
		return nil, errors.New("only responder can process msg1")
	}
	// >= rather than == : engine.go's padHandshake pads the wire message up
	// to the next fixed length bucket for size obfuscation, appending random
	// bytes after msg1TotalLen, so a legitimate Msg1 on the wire is routinely
	// longer than this. Only fields within the first msg1TotalLen bytes are
	// ever read; anything beyond that is padding, never parsed.
	if len(packet) < msg1TotalLen {
		return nil, errors.New("invalid msg1 packet size")
	}

	eRep := packet[0:msg1ERepLen]
	encStatic := packet[msg1ERepLen : msg1ERepLen+msg1StaticCTLen]
	encAuth := packet[msg1ERepLen+msg1StaticCTLen : msg1ERepLen+msg1StaticCTLen+msg1AuthCTLen]
	mac1Rx := packet[msg1ERepLen+msg1StaticCTLen+msg1AuthCTLen : msg1TotalLen]

	// Pre-DH gate: mac1 is a cheap keyed-hash check (requires K_net),
	// verified before any Elligator decode or DH work.
	kMac1I2r, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/i2r", hm.LocalPub[:])
	if err != nil {
		return nil, err
	}
	hMac, _ := blake2s.New256(kMac1I2r)
	hMac.Write(eRep)
	hMac.Write(encStatic)
	hMac.Write(encAuth)
	mac1Calc := hMac.Sum(nil)[:16]
	if subtle.ConstantTimeCompare(mac1Rx, mac1Calc) != 1 {
		return nil, errors.New("msg1 mac1 verification failed")
	}

	copy(hm.RemoteERep[:], eRep)
	hm.RemoteEPub = PublicFromRep(hm.RemoteERep)

	hm.DhEs, err = curve25519.X25519(hm.LocalPriv[:], hm.RemoteEPub[:])
	if err != nil {
		return nil, err
	}
	if isAllZero(hm.DhEs) {
		return nil, errors.New("dh_es produced an all-zero shared secret")
	}

	// Stage 1: decrypt the claimed static public key. See this function's
	// doc comment — this alone is not proof of anything; claimedPub must not
	// be committed to hm.RemotePub or used to look up a Peer until stage 2
	// succeeds below.
	h1, _ := blake2s.New256(nil)
	h1.Write(hm.KNet)
	h1.Write(hm.NID)
	h1.Write([]byte("salt/msg1static"))
	h1.Write(hm.LocalPub[:])
	h1.Write(hm.RemoteEPub[:])
	salt1 := h1.Sum(nil)
	k1, err := HKDFBlake2s(hm.DhEs, salt1, []byte("VEIL hs1 static key"), 32)
	if err != nil {
		return nil, err
	}

	hNonce1, _ := blake2s.New256(k1)
	hNonce1.Write([]byte("nonce/msg1static"))
	hNonce1.Write(hm.RemoteEPub[:])
	hNonce1.Write(hm.LocalPub[:])
	nonce1 := hNonce1.Sum(nil)[:12]

	var ad1 []byte
	ad1 = append(ad1, hm.NID...)
	ad1 = append(ad1, hm.LocalPub[:]...)
	ad1 = append(ad1, hm.RemoteEPub[:]...)

	aead1, err := chacha20poly1305.New(k1)
	if err != nil {
		return nil, err
	}
	staticPt, err := aead1.Open(nil, nonce1, encStatic, ad1)
	zeroBytes(k1)
	if err != nil {
		return nil, errors.New("msg1 static payload decryption failed")
	}
	staticPayload, err := DecodeMsg1StaticPayload(staticPt)
	if err != nil {
		return nil, err
	}
	claimedPub := staticPayload.CPub

	// Stage 2: decrypt timestamp/params under k2 = HKDF(DH(S_i, S_r)) using
	// the just-claimed (still unauthenticated) public key. If the sender
	// forged claimedPub without owning its private key, they cannot have
	// computed dh_ss, so this Open call fails and nothing below it —
	// including committing hm.RemotePub — is ever reached.
	dhSs, err := curve25519.X25519(hm.LocalPriv[:], claimedPub[:])
	if err != nil {
		return nil, err
	}
	if isAllZero(dhSs) {
		return nil, errors.New("dh_ss produced an all-zero shared secret")
	}

	h2, _ := blake2s.New256(nil)
	h2.Write(hm.KNet)
	h2.Write(hm.NID)
	h2.Write([]byte("salt/msg1auth"))
	h2.Write(hm.LocalPub[:])
	h2.Write(hm.RemoteEPub[:])
	h2.Write(claimedPub[:])
	salt2 := h2.Sum(nil)
	k2, err := HKDFBlake2s(dhSs, salt2, []byte("VEIL hs1 auth key"), 32)
	zeroBytes(dhSs)
	if err != nil {
		return nil, err
	}

	hNonce2, _ := blake2s.New256(k2)
	hNonce2.Write([]byte("nonce/msg1auth"))
	hNonce2.Write(hm.RemoteEPub[:])
	hNonce2.Write(hm.LocalPub[:])
	hNonce2.Write(claimedPub[:])
	nonce2 := hNonce2.Sum(nil)[:12]

	var ad2 []byte
	ad2 = append(ad2, hm.NID...)
	ad2 = append(ad2, hm.LocalPub[:]...)
	ad2 = append(ad2, hm.RemoteEPub[:]...)
	ad2 = append(ad2, encStatic...)

	aead2, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, err
	}
	authPt, err := aead2.Open(nil, nonce2, encAuth, ad2)
	zeroBytes(k2)
	if err != nil {
		return nil, errors.New("msg1 auth payload decryption failed")
	}
	authPayload, err := DecodeMsg1AuthPayload(authPt)
	if err != nil {
		return nil, err
	}

	// Both stages succeeded: claimedPub is now trustworthy enough to commit
	// and to act on (the caller may look up/mutate the corresponding Peer).
	hm.RemotePub = claimedPub

	// Transcript binds the wire image (representative) and both ciphertexts,
	// matching the initiator.
	hTh1, _ := blake2s.New256(nil)
	hTh1.Write(hm.NID)
	hTh1.Write([]byte("th1"))
	hTh1.Write(hm.RemoteERep[:])
	hTh1.Write(encStatic)
	hTh1.Write(encAuth)
	hTh1.Write(mac1Rx)
	hm.Th = hTh1.Sum(nil)

	return authPayload, nil
}

func (hm *HandshakeMachine) ConstructMsg2(params *Msg2SessionParams) ([]byte, *transport.TransportKeys, error) {
	if hm.IsInitiator {
		return nil, nil, errors.New("only responder can construct msg2")
	}

	var err error
	hm.LocalEPriv, hm.LocalERep, err = GenerateElligatorKeypair()
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(hm.LocalEPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	copy(hm.LocalEPub[:], pub)

	dhEe, err := curve25519.X25519(hm.LocalEPriv[:], hm.RemoteEPub[:])
	if err != nil {
		return nil, nil, err
	}
	dhSe, err := curve25519.X25519(hm.LocalPriv[:], hm.RemoteEPub[:])
	if err != nil {
		return nil, nil, err
	}
	dhStatic, err := curve25519.X25519(hm.LocalPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, nil, err
	}
	if isAllZero(dhEe) || isAllZero(dhSe) || isAllZero(dhStatic) {
		return nil, nil, errors.New("dh_ee/dh_se/dh_static produced an all-zero shared secret")
	}

	var kHs2Input []byte
	kHs2Input = append(kHs2Input, dhEe...)
	kHs2Input = append(kHs2Input, dhSe...)
	kHs2Input = append(kHs2Input, dhStatic...)
	kHs2Input = append(kHs2Input, hm.pskInput()...)
	zeroBytes(dhEe)
	zeroBytes(dhSe)
	zeroBytes(dhStatic)

	kHs2, err := HKDFBlake2s(kHs2Input, hm.Th, []byte("VEIL hs2 key"), 32)
	if err != nil {
		return nil, nil, err
	}

	hNonce, _ := blake2s.New256(kHs2)
	hNonce.Write([]byte("nonce/msg2"))
	hNonce.Write(hm.LocalEPub[:])
	hNonce.Write(hm.Th)
	nonceMsg2 := hNonce.Sum(nil)[:12]

	var adMsg2 []byte
	adMsg2 = append(adMsg2, hm.Th...)
	adMsg2 = append(adMsg2, hm.NID...)
	adMsg2 = append(adMsg2, hm.LocalEPub[:]...)

	aead, err := chacha20poly1305.New(kHs2)
	if err != nil {
		return nil, nil, err
	}
	ciphertext2 := aead.Seal(nil, nonceMsg2, params.Encode(), adMsg2)

	hConfirmKey, _ := blake2s.New256(kHs2)
	hConfirmKey.Write([]byte("confirm/msg2"))
	kConfirm := hConfirmKey.Sum(nil)

	// confirm, MAC1 and the transcript bind the wire image (representative).
	hConfirm, _ := blake2s.New256(kConfirm)
	hConfirm.Write(hm.Th)
	hConfirm.Write(hm.LocalERep[:])
	hConfirm.Write(ciphertext2)
	confirm := hConfirm.Sum(nil)[:16]

	kMac1R2i, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/r2i", hm.LocalPub[:])
	if err != nil {
		return nil, nil, err
	}

	hMac, _ := blake2s.New256(kMac1R2i)
	hMac.Write(hm.LocalERep[:])
	hMac.Write(ciphertext2)
	hMac.Write(confirm)
	mac1 := hMac.Sum(nil)[:16]

	var packet []byte
	packet = append(packet, hm.LocalERep[:]...)
	packet = append(packet, ciphertext2...)
	packet = append(packet, confirm...)
	packet = append(packet, mac1...)

	// Update transcript th2
	hTh2, _ := blake2s.New256(nil)
	hTh2.Write(hm.Th)
	hTh2.Write([]byte("th2"))
	hTh2.Write(hm.LocalERep[:])
	hTh2.Write(ciphertext2)
	hTh2.Write(confirm)
	hTh2.Write(mac1)
	hm.Th = hTh2.Sum(nil)

	// Compute Master and Transport Keys
	keys, err := hm.computeTransportKeys(kHs2Input, params)
	zeroBytes(kHs2Input)
	zeroBytes(kHs2)
	return packet, keys, err
}

// msg2TotalLen is the fixed Msg2 wire size now that the variable prefix is
// gone (P0.6): e_i_rep(32) + ciphertext2(112, Msg2SessionParams(96)+tag(16))
// + confirm(16) + mac1(16).
const msg2TotalLen = 32 + 112 + 16 + 16

func (hm *HandshakeMachine) ProcessMsg2(packet []byte) (*Msg2SessionParams, *transport.TransportKeys, error) {
	if !hm.IsInitiator {
		return nil, nil, errors.New("only initiator can process msg2")
	}
	// >= rather than == : see ProcessMsg1's identical comment — padHandshake
	// pads the wire message to a fixed length bucket, so a legitimate Msg2 is
	// routinely longer than msg2TotalLen.
	if len(packet) < msg2TotalLen {
		return nil, nil, errors.New("invalid msg2 packet size")
	}

	kMac1R2i, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/r2i", hm.RemotePub[:])
	if err != nil {
		return nil, nil, err
	}

	eRep := packet[0:32]
	ciphertext2 := packet[32:144]
	confirmRx := packet[144:160]
	mac1Rx := packet[160:176]

	hMac, _ := blake2s.New256(kMac1R2i)
	hMac.Write(eRep)
	hMac.Write(ciphertext2)
	hMac.Write(confirmRx)
	mac1Calc := hMac.Sum(nil)[:16]

	if subtle.ConstantTimeCompare(mac1Rx, mac1Calc) != 1 {
		return nil, nil, errors.New("msg2 mac1 verification failed")
	}

	var params *Msg2SessionParams

	copy(hm.RemoteERep[:], eRep)
	hm.RemoteEPub = PublicFromRep(hm.RemoteERep)

	dhEe, err := curve25519.X25519(hm.LocalEPriv[:], hm.RemoteEPub[:])
	if err != nil {
		return nil, nil, err
	}
	dhSe, err := curve25519.X25519(hm.LocalEPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, nil, err
	}
	dhStatic, err := curve25519.X25519(hm.LocalPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, nil, err
	}
	if isAllZero(dhEe) || isAllZero(dhSe) || isAllZero(dhStatic) {
		return nil, nil, errors.New("dh_ee/dh_se/dh_static produced an all-zero shared secret")
	}

	var kHs2Input []byte
	kHs2Input = append(kHs2Input, dhEe...)
	kHs2Input = append(kHs2Input, dhSe...)
	kHs2Input = append(kHs2Input, dhStatic...)
	kHs2Input = append(kHs2Input, hm.pskInput()...)
	zeroBytes(dhEe)
	zeroBytes(dhSe)
	zeroBytes(dhStatic)

	kHs2, err := HKDFBlake2s(kHs2Input, hm.Th, []byte("VEIL hs2 key"), 32)
	if err != nil {
		return nil, nil, err
	}

	hConfirmKey, _ := blake2s.New256(kHs2)
	hConfirmKey.Write([]byte("confirm/msg2"))
	kConfirm := hConfirmKey.Sum(nil)

	hConfirm, _ := blake2s.New256(kConfirm)
	hConfirm.Write(hm.Th)
	hConfirm.Write(hm.RemoteERep[:])
	hConfirm.Write(ciphertext2)
	confirmCalc := hConfirm.Sum(nil)[:16]

	if subtle.ConstantTimeCompare(confirmRx, confirmCalc) != 1 {
		return nil, nil, errors.New("msg2 confirm verification failed")
	}

	hNonce, _ := blake2s.New256(kHs2)
	hNonce.Write([]byte("nonce/msg2"))
	hNonce.Write(hm.RemoteEPub[:])
	hNonce.Write(hm.Th)
	nonceMsg2 := hNonce.Sum(nil)[:12]

	var adMsg2 []byte
	adMsg2 = append(adMsg2, hm.Th...)
	adMsg2 = append(adMsg2, hm.NID...)
	adMsg2 = append(adMsg2, hm.RemoteEPub[:]...)

	aead, err := chacha20poly1305.New(kHs2)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(nil, nonceMsg2, ciphertext2, adMsg2)
	if err != nil {
		return nil, nil, errors.New("msg2 decryption failed")
	}

	params, err = DecodeMsg2SessionParams(plaintext)
	if err != nil {
		return nil, nil, err
	}

	// Update transcript th2
	hTh2, _ := blake2s.New256(nil)
	hTh2.Write(hm.Th)
	hTh2.Write([]byte("th2"))
	hTh2.Write(hm.RemoteERep[:])
	hTh2.Write(ciphertext2)
	hTh2.Write(confirmRx)
	hTh2.Write(mac1Rx)
	hm.Th = hTh2.Sum(nil)

	keys, err := hm.computeTransportKeys(kHs2Input, params)
	zeroBytes(kHs2Input)
	zeroBytes(kHs2)
	return params, keys, err
}

func (hm *HandshakeMachine) computeTransportKeys(kHs2Input []byte, params *Msg2SessionParams) (*transport.TransportKeys, error) {
	// K_master = HKDF-BLAKE2s(input = dh_es || dh_ee || dh_se || dh_static || psk_input, salt = th2)
	var kMasterInput []byte
	kMasterInput = append(kMasterInput, hm.DhEs...)
	kMasterInput = append(kMasterInput, kHs2Input...)

	kMaster, err := HKDFBlake2s(kMasterInput, hm.Th, []byte("VEIL session master"), 32)
	if err != nil {
		return nil, err
	}

	kI2R, _ := HKDFBlake2s(kMaster, hm.Th, []byte("transport i2r key"), 32)
	kR2I, _ := HKDFBlake2s(kMaster, hm.Th, []byte("transport r2i key"), 32)
	kTagI2R, _ := HKDFBlake2s(kMaster, hm.Th, []byte("tag i2r key"), 32)
	kTagR2I, _ := HKDFBlake2s(kMaster, hm.Th, []byte("tag r2i key"), 32)

	zeroBytes(kMasterInput)
	zeroBytes(kMaster)
	zeroBytes(hm.DhEs)

	hCtx, _ := blake2s.New256(nil)
	hCtx.Write(hm.NID)
	hCtx.Write(hm.Th)
	hCtx.Write([]byte("session context"))
	sessionCtx := hCtx.Sum(nil)

	keys := &transport.TransportKeys{
		SessionContext: sessionCtx,
		NonceSeed:      make([]byte, 32),
	}
	copy(keys.NonceSeed, params.SessionNonceSeed[:])

	if hm.IsInitiator {
		keys.KSend = kI2R
		keys.KRecv = kR2I
		keys.KTagSend = kTagI2R
		keys.KTagRecv = kTagR2I
	} else {
		keys.KSend = kR2I
		keys.KRecv = kI2R
		keys.KTagSend = kTagR2I
		keys.KTagRecv = kTagI2R
	}

	return keys, nil
}
