package core

import (
	"bytes"
	"testing"

	"github.com/veil-proto/veil/transport"
	"golang.org/x/crypto/curve25519"
)

// TestHandshakeEndToEnd runs a full Msg1/Msg2 exchange through the
// HandshakeMachine and asserts both sides derive matching, correctly-oriented
// transport keys and can then round-trip a transport packet. This is the
// integration gate for the Elligator2 wire-image change.
func TestHandshakeEndToEnd(t *testing.T) {
	nid := DeriveNID("test-net", "light")
	kNet := bytes.Repeat([]byte{0x11}, 32)

	// Static keypairs.
	var cPriv, cPub, sPriv, sPub [32]byte
	cp, cr, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cPriv = cp
	_ = cr
	cpub, _ := curve25519.X25519(cPriv[:], curve25519.Basepoint)
	copy(cPub[:], cpub)

	sp, _, err := GenerateElligatorKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sPriv = sp
	spub, _ := curve25519.X25519(sPriv[:], curve25519.Basepoint)
	copy(sPub[:], spub)

	// Initiator knows the responder static public key.
	initiator := NewHandshakeMachine(true, kNet, nid, cPriv, sPub)
	// Responder knows K_net/NID and its own key; it learns C_pub from Msg1.
	responder := NewHandshakeMachine(false, kNet, nid, sPriv, [32]byte{})

	// Msg1
	msg1, err := initiator.ConstructMsg1()
	if err != nil {
		t.Fatalf("ConstructMsg1: %v", err)
	}
	_, err = responder.ProcessMsg1(msg1)
	if err != nil {
		t.Fatalf("ProcessMsg1: %v", err)
	}
	if !bytes.Equal(responder.RemotePub[:], cPub[:]) {
		t.Fatalf("responder recovered wrong C_pub\n got=%x\nwant=%x", responder.RemotePub, cPub)
	}

	// Msg2
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	params := &Msg2SessionParams{TagLen: 16, SessionNonceSeed: seed}
	msg2, srvKeys, err := responder.ConstructMsg2(params)
	if err != nil {
		t.Fatalf("ConstructMsg2: %v", err)
	}
	_, cliKeys, err := initiator.ProcessMsg2(msg2)
	if err != nil {
		t.Fatalf("ProcessMsg2: %v", err)
	}

	// Directional keys must cross over.
	if !bytes.Equal(cliKeys.KSend, srvKeys.KRecv) || !bytes.Equal(cliKeys.KRecv, srvKeys.KSend) {
		t.Fatal("transport keys do not cross-match")
	}
	if !bytes.Equal(cliKeys.SessionContext, srvKeys.SessionContext) {
		t.Fatal("session context mismatch")
	}

	// Transport round-trip: client -> server.
	inner := []byte("hello veil v0.3 over elligator2")
	wire, err := transport.EncapsulateTransport(cliKeys, 0, inner, 0, 16)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	got, err := transport.DecapsulateTransport(srvKeys, 0, wire, 16)
	if err != nil {
		t.Fatalf("decap: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("transport payload mismatch: got %q", got)
	}
}
