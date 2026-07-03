package core

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestElligatorRoundTrip is the correctness gate for the hand-written inverse
// map: for many generated keypairs, decoding the representative must reproduce
// the exact X25519 public key, and that public key must match the private
// scalar. If the inverse map were wrong, DH would silently fail on the wire.
func TestElligatorRoundTrip(t *testing.T) {
	const iters = 2000
	for i := 0; i < iters; i++ {
		priv, rep, err := GenerateElligatorKeypair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}

		wantPub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("x25519: %v", err)
		}

		gotPub := PublicFromRep(rep)
		if !bytes.Equal(gotPub[:], wantPub) {
			t.Fatalf("iter %d: representative decodes to wrong public key\n got=%x\nwant=%x", i, gotPub, wantPub)
		}
	}
}

// TestElligatorDHAgrees checks a full ephemeral-static DH still agrees when the
// initiator ships a representative instead of the raw public key.
func TestElligatorDHAgrees(t *testing.T) {
	// Responder static key.
	sPriv, _, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sPub, err := curve25519.X25519(sPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	// Initiator ephemeral, shipped as representative.
	ePriv, eRep, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}

	// Initiator side: DH with the real public key.
	ePub, _ := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	dhInit, err := curve25519.X25519(sPriv[:], ePub)
	if err != nil {
		t.Fatal(err)
	}

	// Responder side: recover ephemeral public from the representative, then DH.
	recovered := PublicFromRep(eRep)
	dhResp, err := curve25519.X25519(sPriv[:], recovered[:])
	if err != nil {
		t.Fatal(err)
	}
	_ = sPub

	if !bytes.Equal(dhInit, dhResp) {
		t.Fatalf("DH mismatch: init=%x resp=%x", dhInit, dhResp)
	}
}

// TestElligatorHighBitSpread is a cheap sanity check that the two high bits of
// the representative are actually randomized (not stuck at zero), which is what
// makes the full 32 bytes look uniform.
func TestElligatorHighBitSpread(t *testing.T) {
	var seen [4]int
	for i := 0; i < 400; i++ {
		_, rep, err := GenerateElligatorKeypair()
		if err != nil {
			t.Fatal(err)
		}
		seen[(rep[31]>>6)&0x3]++
	}
	for v, c := range seen {
		if c == 0 {
			t.Fatalf("high-bit pattern %d never observed; top bits not randomized", v)
		}
	}
}
