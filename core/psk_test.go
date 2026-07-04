package core

import (
	"bytes"
	"testing"

	"github.com/veil-proto/veil/transport"
	"golang.org/x/crypto/curve25519"
)

// pskHandshakeRaw runs one full Msg1/Msg2 exchange with the given PSKs set on
// the initiator and responder respectively, mirroring
// TestHandshakeEndToEnd's setup but parameterized on PSK so the tests below
// can compare PSK-present vs PSK-absent behavior.
func pskHandshakeRaw(t *testing.T, initiatorPSK, responderPSK []byte) (cli, srv *transport.TransportKeys, err error) {
	t.Helper()

	nid := DeriveNID("psk-test-net", "light")
	kNet := bytes.Repeat([]byte{0x22}, 32)

	var cPriv, sPriv, sPub [32]byte
	cp, _, gerr := GenerateElligatorKeypair()
	if gerr != nil {
		t.Fatal(gerr)
	}
	cPriv = cp

	sp, _, gerr := GenerateElligatorKeypair()
	if gerr != nil {
		t.Fatal(gerr)
	}
	sPriv = sp
	spub, _ := curve25519.X25519(sPriv[:], curve25519.Basepoint)
	copy(sPub[:], spub)

	initiator := NewHandshakeMachine(true, kNet, nid, cPriv, sPub)
	initiator.PSK = initiatorPSK
	responder := NewHandshakeMachine(false, kNet, nid, sPriv, [32]byte{})

	msg1, err := initiator.ConstructMsg1()
	if err != nil {
		return nil, nil, err
	}
	if _, err = responder.ProcessMsg1(msg1); err != nil {
		return nil, nil, err
	}
	responder.PSK = responderPSK

	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	params := &Msg2SessionParams{TagLen: 16, SessionNonceSeed: seed}
	msg2, srvKeys, err := responder.ConstructMsg2(params)
	if err != nil {
		return nil, nil, err
	}
	_, cliKeys, err := initiator.ProcessMsg2(msg2)
	if err != nil {
		return nil, nil, err
	}
	return cliKeys, srvKeys, nil
}

func TestPSK_AbsentMatchesHistoricalZeroBehavior(t *testing.T) {
	// Neither side configures a PSK: the handshake must succeed with
	// cross-matching keys, exactly as it always has (all-zero PSK KDF input
	// on both sides).
	cli, srv, err := pskHandshakeRaw(t, nil, nil)
	if err != nil {
		t.Fatalf("PSK-less handshake failed: %v", err)
	}
	if !bytes.Equal(cli.KSend, srv.KRecv) || !bytes.Equal(cli.KRecv, srv.KSend) {
		t.Fatal("PSK-less transport keys do not cross-match")
	}
}

func TestPSK_MatchingPSKSucceedsAndChangesDerivedKeys(t *testing.T) {
	psk := bytes.Repeat([]byte{0x77}, 32)

	cliNoPSK, _, err := pskHandshakeRaw(t, nil, nil)
	if err != nil {
		t.Fatalf("PSK-less handshake failed: %v", err)
	}

	cliPSK, srvPSK, err := pskHandshakeRaw(t, psk, psk)
	if err != nil {
		t.Fatalf("matching-PSK handshake failed: %v", err)
	}
	if !bytes.Equal(cliPSK.KSend, srvPSK.KRecv) || !bytes.Equal(cliPSK.KRecv, srvPSK.KSend) {
		t.Fatal("matching-PSK transport keys do not cross-match")
	}

	// The whole point of wiring the PSK into the KDF: configuring one must
	// actually change the derived session keys versus the PSK-less case.
	if bytes.Equal(cliNoPSK.KSend, cliPSK.KSend) {
		t.Fatal("PSK-present derived keys are identical to PSK-absent — PSK is not being mixed into the KDF")
	}
}

func TestPSK_MismatchedPSKFailsHandshake(t *testing.T) {
	pskA := bytes.Repeat([]byte{0x11}, 32)
	pskB := bytes.Repeat([]byte{0x22}, 32)

	if _, _, err := pskHandshakeRaw(t, pskA, pskB); err == nil {
		t.Fatal("handshake with mismatched PSKs must fail confirm verification, but it succeeded")
	}
}
