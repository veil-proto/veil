package core

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestZeroSecrets_ZeroesEphemeralButNotSharedKNetOrPSK verifies P0.5's
// corrected scope: ZeroSecrets must wipe the per-handshake ephemeral private
// key, but must never touch KNet/PSK, which are shared references into
// long-lived Engine/Peer config state (see ZeroSecrets' doc comment for why
// the roadmap's original "zero hm.KNet and hm.PSK" suggestion would have
// corrupted every future handshake on the same Engine/Peer).
func TestZeroSecrets_ZeroesEphemeralButNotSharedKNetOrPSK(t *testing.T) {
	kNet := bytes.Repeat([]byte{0x44}, 32)
	psk := bytes.Repeat([]byte{0x55}, 32)
	nid := DeriveNID("zeroize-test-net", "light")

	var localPriv, remotePub [32]byte
	lp, _, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	localPriv = lp

	rp, _, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	remotePubBytes, err := curve25519.X25519(rp[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(remotePub[:], remotePubBytes)

	hm := NewHandshakeMachine(true, kNet, nid, localPriv, remotePub)
	hm.PSK = psk

	if _, err := hm.ConstructMsg1(); err != nil {
		t.Fatalf("ConstructMsg1: %v", err)
	}
	if hm.LocalEPriv == ([32]byte{}) {
		t.Fatal("test setup broken: LocalEPriv should be populated after ConstructMsg1")
	}

	hm.ZeroSecrets()

	if hm.LocalEPriv != ([32]byte{}) {
		t.Fatal("ZeroSecrets must zero LocalEPriv")
	}
	if !bytes.Equal(hm.KNet, kNet) {
		t.Fatal("ZeroSecrets must not modify KNet — it's a shared reference into long-lived config state")
	}
	if !bytes.Equal(hm.PSK, psk) {
		t.Fatal("ZeroSecrets must not modify PSK — it's a shared reference into the Peer's config state")
	}
}
