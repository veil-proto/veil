package core

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// TestProcessMsg1_ForgedStaticClaimIsRejectedBeforeCommit is the regression
// test for P0.3 (VEIL-Combined-Roadmap.md): an attacker who knows a victim's
// static *public* key (public knowledge — every peer's pubkey is exchanged
// out of band) but not its private key must not be able to get ProcessMsg1
// to report success, or to commit hm.RemotePub to the victim's key at all.
//
// The attacker here plays by the old (broken) rules: they can correctly
// build stage 1 (encStatic) — it only requires dh_es = DH(e_i, S_r), which
// needs no secret of the victim's — but they cannot build a stage 2
// (encAuth) that decrypts under k2 = HKDF(DH(S_i, S_r)), because they have
// neither the victim's static private key nor the responder's. Before the
// P0.3 fix, the single-ciphertext Msg1 format meant successfully forging
// stage 1 alone was enough for ProcessMsg1 to return success and hand the
// caller (engine.go's handleHandshake) a victim CPub to look up and mutate
// (CheckAndUpdateMsg1Timestamp) — a standing DoS the victim could not detect
// or recover from. This test proves that no longer works.
func TestProcessMsg1_ForgedStaticClaimIsRejectedBeforeCommit(t *testing.T) {
	nid := DeriveNID("forge-test-net", "light")
	kNet := bytes.Repeat([]byte{0x33}, 32)

	// Responder's real keypair.
	rPriv, _, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rPubBytes, _ := curve25519.X25519(rPriv[:], curve25519.Basepoint)
	var rPub [32]byte
	copy(rPub[:], rPubBytes)

	// Victim's real keypair — the attacker knows victimPub (public) only,
	// never victimPriv.
	victimPriv, _, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	victimPubBytes, _ := curve25519.X25519(victimPriv[:], curve25519.Basepoint)
	var victimPub [32]byte
	copy(victimPub[:], victimPubBytes)

	// Attacker's own ephemeral keypair (self-chosen, no secret needed).
	attackerEPriv, attackerERep, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	attackerEPubBytes, _ := curve25519.X25519(attackerEPriv[:], curve25519.Basepoint)
	var attackerEPub [32]byte
	copy(attackerEPub[:], attackerEPubBytes)

	// Attacker computes dh_es = DH(e_attacker, S_r) — needs only public S_r.
	dhEs, err := curve25519.X25519(attackerEPriv[:], rPub[:])
	if err != nil {
		t.Fatal(err)
	}

	h1, _ := blake2s.New256(nil)
	h1.Write(kNet)
	h1.Write(nid)
	h1.Write([]byte("salt/msg1static"))
	h1.Write(rPub[:])
	h1.Write(attackerEPub[:])
	salt1 := h1.Sum(nil)
	k1, err := HKDFBlake2s(dhEs, salt1, []byte("VEIL hs1 static key"), 32)
	if err != nil {
		t.Fatal(err)
	}

	hNonce1, _ := blake2s.New256(k1)
	hNonce1.Write([]byte("nonce/msg1static"))
	hNonce1.Write(attackerEPub[:])
	hNonce1.Write(rPub[:])
	nonce1 := hNonce1.Sum(nil)[:12]

	var ad1 []byte
	ad1 = append(ad1, nid...)
	ad1 = append(ad1, rPub[:]...)
	ad1 = append(ad1, attackerEPub[:]...)

	aead1, err := chacha20poly1305.New(k1)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker successfully forges stage 1, claiming the victim's pubkey.
	staticPayload := &Msg1StaticPayload{CPub: victimPub}
	encStatic := aead1.Seal(nil, nonce1, staticPayload.Encode(), ad1)

	// Attacker cannot compute dh_ss = DH(victimPriv, S_r) or DH(S_i, rPriv):
	// they have neither private key. The best they can do is encrypt stage 2
	// under a key derived from something they *do* control (e.g. their own
	// ephemeral secret again, or random bytes) — simulate the strongest
	// plausible forgery attempt with random garbage ciphertext of the right
	// length, since no key derivable from public information alone will ever
	// match the responder's k2.
	encAuth := make([]byte, msg1AuthCTLen)
	if _, err := rand.Read(encAuth); err != nil {
		t.Fatal(err)
	}

	kMac1I2r, err := DeriveMac1Key(kNet, nid, "mac1/i2r", rPub[:])
	if err != nil {
		t.Fatal(err)
	}
	hMac, _ := blake2s.New256(kMac1I2r)
	hMac.Write(attackerERep[:])
	hMac.Write(encStatic)
	hMac.Write(encAuth)
	mac1 := hMac.Sum(nil)[:16]

	var forgedPacket []byte
	forgedPacket = append(forgedPacket, attackerERep[:]...)
	forgedPacket = append(forgedPacket, encStatic...)
	forgedPacket = append(forgedPacket, encAuth...)
	forgedPacket = append(forgedPacket, mac1...)

	responder := NewHandshakeMachine(false, kNet, nid, rPriv, [32]byte{})
	_, err = responder.ProcessMsg1(forgedPacket)
	if err == nil {
		t.Fatal("forged Msg1 (attacker-claimed victim CPub, no victim private key) must be rejected")
	}
	if responder.RemotePub != ([32]byte{}) {
		t.Fatal("ProcessMsg1 must not commit RemotePub before stage 2 (dh_ss-gated) succeeds")
	}
}
