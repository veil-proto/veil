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

func (hm *HandshakeMachine) ConstructMsg1(prefix []byte) ([]byte, error) {
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

	h, _ := blake2s.New256(nil)
	h.Write(hm.KNet)
	h.Write(hm.NID)
	h.Write([]byte("salt/msg1"))
	h.Write(hm.RemotePub[:])
	h.Write(hm.LocalEPub[:])
	salt1 := h.Sum(nil)

	kHs1, err := HKDFBlake2s(hm.DhEs, salt1, []byte("VEIL hs1 key"), 32)
	if err != nil {
		return nil, err
	}

	hNonce, _ := blake2s.New256(kHs1)
	hNonce.Write([]byte("nonce/msg1"))
	hNonce.Write(hm.LocalEPub[:])
	hNonce.Write(hm.RemotePub[:])
	hNonce.Write(prefix)
	nonceMsg1 := hNonce.Sum(nil)[:12]

	var adMsg1 []byte
	adMsg1 = append(adMsg1, hm.NID...)
	adMsg1 = append(adMsg1, hm.RemotePub[:]...)
	adMsg1 = append(adMsg1, hm.LocalEPub[:]...)
	adMsg1 = append(adMsg1, prefix...)

	var payload Msg1Payload
	copy(payload.CPub[:], hm.LocalPub[:])
	payload.Timestamp = EncodeMonotonicTimestamp()
	payload.RequestedTagLen = 16

	aead, err := chacha20poly1305.New(kHs1)
	if err != nil {
		return nil, err
	}
	ciphertext1 := aead.Seal(nil, nonceMsg1, payload.Encode(), adMsg1)

	kMac1I2r, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/i2r", hm.RemotePub[:])
	if err != nil {
		return nil, err
	}

	// MAC1 and the transcript bind the exact wire image (Elligator2
	// representative), so the responder can verify MAC1 before decoding the
	// representative into a curve point.
	hMac, _ := blake2s.New256(kMac1I2r)
	hMac.Write(prefix)
	hMac.Write(hm.LocalERep[:])
	hMac.Write(ciphertext1)
	mac1 := hMac.Sum(nil)[:16]

	var packet []byte
	packet = append(packet, prefix...)
	packet = append(packet, hm.LocalERep[:]...)
	packet = append(packet, ciphertext1...)
	packet = append(packet, mac1...)

	// Transcript
	hTh1, _ := blake2s.New256(nil)
	hTh1.Write(hm.NID)
	hTh1.Write([]byte("th1"))
	hTh1.Write(prefix)
	hTh1.Write(hm.LocalERep[:])
	hTh1.Write(ciphertext1)
	hTh1.Write(mac1)
	hm.Th = hTh1.Sum(nil)

	return packet, nil
}

func (hm *HandshakeMachine) ProcessMsg1(packet []byte, allowedPrefixes []int) (*Msg1Payload, []byte, error) {
	if hm.IsInitiator {
		return nil, nil, errors.New("only responder can process msg1")
	}

	kMac1I2r, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/i2r", hm.LocalPub[:])
	if err != nil {
		return nil, nil, err
	}

	var parsedPrefix []byte
	var parsedERep []byte
	var ciphertext1 []byte
	var mac1Rx []byte

	var payload *Msg1Payload
	var validPrefix int = -1

	for _, p := range allowedPrefixes {
		if len(packet) < p+32+100+16 {
			continue
		}

		prefix := packet[0:p]
		eRep := packet[p : p+32]
		ctx := packet[p+32 : p+132]
		mac := packet[p+132 : p+148]

		// MAC1 is verified over the wire image (representative), before any
		// curve decode or X25519 — this is the pre-DH gate.
		hMac, _ := blake2s.New256(kMac1I2r)
		hMac.Write(prefix)
		hMac.Write(eRep)
		hMac.Write(ctx)
		mac1Calc := hMac.Sum(nil)[:16]

		if subtle.ConstantTimeCompare(mac, mac1Calc) == 1 {
			parsedPrefix = prefix
			parsedERep = eRep
			ciphertext1 = ctx
			mac1Rx = mac
			validPrefix = p
			break
		}
	}

	if validPrefix == -1 {
		return nil, nil, errors.New("msg1 mac1 verification failed or invalid packet size")
	}

	copy(hm.RemoteERep[:], parsedERep)
	// Decode the Elligator2 representative into the real ephemeral public key.
	hm.RemoteEPub = PublicFromRep(hm.RemoteERep)

	hm.DhEs, err = curve25519.X25519(hm.LocalPriv[:], hm.RemoteEPub[:])
	if err != nil {
		return nil, nil, err
	}
	if isAllZero(hm.DhEs) {
		return nil, nil, errors.New("dh_es produced an all-zero shared secret")
	}

	h, _ := blake2s.New256(nil)
	h.Write(hm.KNet)
	h.Write(hm.NID)
	h.Write([]byte("salt/msg1"))
	h.Write(hm.LocalPub[:])
	h.Write(hm.RemoteEPub[:])
	salt1 := h.Sum(nil)

	kHs1, err := HKDFBlake2s(hm.DhEs, salt1, []byte("VEIL hs1 key"), 32)
	if err != nil {
		return nil, nil, err
	}

	hNonce, _ := blake2s.New256(kHs1)
	hNonce.Write([]byte("nonce/msg1"))
	hNonce.Write(hm.RemoteEPub[:])
	hNonce.Write(hm.LocalPub[:])
	hNonce.Write(parsedPrefix)
	nonceMsg1 := hNonce.Sum(nil)[:12]

	var adMsg1 []byte
	adMsg1 = append(adMsg1, hm.NID...)
	adMsg1 = append(adMsg1, hm.LocalPub[:]...)
	adMsg1 = append(adMsg1, hm.RemoteEPub[:]...)
	adMsg1 = append(adMsg1, parsedPrefix...)

	aead, err := chacha20poly1305.New(kHs1)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(nil, nonceMsg1, ciphertext1, adMsg1)
	if err != nil {
		return nil, nil, errors.New("msg1 decryption failed")
	}

	payload, err = DecodeMsg1Payload(plaintext)
	if err != nil {
		return nil, nil, err
	}

	copy(hm.RemotePub[:], payload.CPub[:])

	// Transcript binds the wire image (representative), matching the initiator.
	hTh1, _ := blake2s.New256(nil)
	hTh1.Write(hm.NID)
	hTh1.Write([]byte("th1"))
	hTh1.Write(parsedPrefix)
	hTh1.Write(hm.RemoteERep[:])
	hTh1.Write(ciphertext1)
	hTh1.Write(mac1Rx)
	hm.Th = hTh1.Sum(nil)

	return payload, parsedPrefix, nil
}

func (hm *HandshakeMachine) ConstructMsg2(prefix2 []byte, params *Msg2SessionParams) ([]byte, *transport.TransportKeys, error) {
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
	hNonce.Write(prefix2)
	nonceMsg2 := hNonce.Sum(nil)[:12]

	var adMsg2 []byte
	adMsg2 = append(adMsg2, hm.Th...)
	adMsg2 = append(adMsg2, hm.NID...)
	adMsg2 = append(adMsg2, hm.LocalEPub[:]...)
	adMsg2 = append(adMsg2, prefix2...)

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
	hConfirm.Write(prefix2)
	hConfirm.Write(hm.LocalERep[:])
	hConfirm.Write(ciphertext2)
	confirm := hConfirm.Sum(nil)[:16]

	kMac1R2i, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/r2i", hm.LocalPub[:])
	if err != nil {
		return nil, nil, err
	}

	hMac, _ := blake2s.New256(kMac1R2i)
	hMac.Write(prefix2)
	hMac.Write(hm.LocalERep[:])
	hMac.Write(ciphertext2)
	hMac.Write(confirm)
	mac1 := hMac.Sum(nil)[:16]

	var packet []byte
	packet = append(packet, prefix2...)
	packet = append(packet, hm.LocalERep[:]...)
	packet = append(packet, ciphertext2...)
	packet = append(packet, confirm...)
	packet = append(packet, mac1...)

	// Update transcript th2
	hTh2, _ := blake2s.New256(nil)
	hTh2.Write(hm.Th)
	hTh2.Write([]byte("th2"))
	hTh2.Write(prefix2)
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

func (hm *HandshakeMachine) ProcessMsg2(packet []byte, allowedPrefixes []int) (*Msg2SessionParams, *transport.TransportKeys, []byte, error) {
	if !hm.IsInitiator {
		return nil, nil, nil, errors.New("only initiator can process msg2")
	}

	kMac1R2i, err := DeriveMac1Key(hm.KNet, hm.NID, "mac1/r2i", hm.RemotePub[:])
	if err != nil {
		return nil, nil, nil, err
	}

	var parsedPrefix []byte
	var parsedERep []byte
	var ciphertext2 []byte
	var confirmRx []byte
	var mac1Rx []byte

	var params *Msg2SessionParams
	var validPrefix int = -1

	for _, p := range allowedPrefixes {
		if len(packet) < p+32+112+16+16 {
			continue
		}

		prefix := packet[0:p]
		eRep := packet[p : p+32]
		ctx := packet[p+32 : p+144]
		confirm := packet[p+144 : p+160]
		mac := packet[p+160 : p+176]

		hMac, _ := blake2s.New256(kMac1R2i)
		hMac.Write(prefix)
		hMac.Write(eRep)
		hMac.Write(ctx)
		hMac.Write(confirm)
		mac1Calc := hMac.Sum(nil)[:16]

		if subtle.ConstantTimeCompare(mac, mac1Calc) == 1 {
			parsedPrefix = prefix
			parsedERep = eRep
			ciphertext2 = ctx
			confirmRx = confirm
			mac1Rx = mac
			validPrefix = p
			break
		}
	}

	if validPrefix == -1 {
		return nil, nil, nil, errors.New("msg2 mac1 verification failed")
	}

	copy(hm.RemoteERep[:], parsedERep)
	hm.RemoteEPub = PublicFromRep(hm.RemoteERep)

	dhEe, err := curve25519.X25519(hm.LocalEPriv[:], hm.RemoteEPub[:])
	if err != nil {
		return nil, nil, nil, err
	}
	dhSe, err := curve25519.X25519(hm.LocalEPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, nil, nil, err
	}
	dhStatic, err := curve25519.X25519(hm.LocalPriv[:], hm.RemotePub[:])
	if err != nil {
		return nil, nil, nil, err
	}
	if isAllZero(dhEe) || isAllZero(dhSe) || isAllZero(dhStatic) {
		return nil, nil, nil, errors.New("dh_ee/dh_se/dh_static produced an all-zero shared secret")
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
		return nil, nil, nil, err
	}

	hConfirmKey, _ := blake2s.New256(kHs2)
	hConfirmKey.Write([]byte("confirm/msg2"))
	kConfirm := hConfirmKey.Sum(nil)

	hConfirm, _ := blake2s.New256(kConfirm)
	hConfirm.Write(hm.Th)
	hConfirm.Write(parsedPrefix)
	hConfirm.Write(hm.RemoteERep[:])
	hConfirm.Write(ciphertext2)
	confirmCalc := hConfirm.Sum(nil)[:16]

	if subtle.ConstantTimeCompare(confirmRx, confirmCalc) != 1 {
		return nil, nil, nil, errors.New("msg2 confirm verification failed")
	}

	hNonce, _ := blake2s.New256(kHs2)
	hNonce.Write([]byte("nonce/msg2"))
	hNonce.Write(hm.RemoteEPub[:])
	hNonce.Write(hm.Th)
	hNonce.Write(parsedPrefix)
	nonceMsg2 := hNonce.Sum(nil)[:12]

	var adMsg2 []byte
	adMsg2 = append(adMsg2, hm.Th...)
	adMsg2 = append(adMsg2, hm.NID...)
	adMsg2 = append(adMsg2, hm.RemoteEPub[:]...)
	adMsg2 = append(adMsg2, parsedPrefix...)

	aead, err := chacha20poly1305.New(kHs2)
	if err != nil {
		return nil, nil, nil, err
	}
	plaintext, err := aead.Open(nil, nonceMsg2, ciphertext2, adMsg2)
	if err != nil {
		return nil, nil, nil, errors.New("msg2 decryption failed")
	}

	params, err = DecodeMsg2SessionParams(plaintext)
	if err != nil {
		return nil, nil, nil, err
	}

	// Update transcript th2
	hTh2, _ := blake2s.New256(nil)
	hTh2.Write(hm.Th)
	hTh2.Write([]byte("th2"))
	hTh2.Write(parsedPrefix)
	hTh2.Write(hm.RemoteERep[:])
	hTh2.Write(ciphertext2)
	hTh2.Write(confirmRx)
	hTh2.Write(mac1Rx)
	hm.Th = hTh2.Sum(nil)

	keys, err := hm.computeTransportKeys(kHs2Input, params)
	zeroBytes(kHs2Input)
	zeroBytes(kHs2)
	return params, keys, parsedPrefix, err
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
