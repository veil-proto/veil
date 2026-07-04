package engine

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/veil-proto/veil/core"
	recordv1 "github.com/veil-proto/veil/record/v1"
	"github.com/veil-proto/veil/transport"
)

// runHandshake performs a full Msg1/Msg2 exchange and returns the initiator and
// responder transport keys.
func runHandshake(t *testing.T, cPriv, sPriv [32]byte, kNet, nid []byte) (cli, srv *transport.TransportKeys) {
	t.Helper()
	sPubB, _ := curve25519.X25519(sPriv[:], curve25519.Basepoint)
	var sPub [32]byte
	copy(sPub[:], sPubB)

	initiator := core.NewHandshakeMachine(true, kNet, nid, cPriv, sPub)
	responder := core.NewHandshakeMachine(false, kNet, nid, sPriv, [32]byte{})

	msg1, err := initiator.ConstructMsg1()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.ProcessMsg1(msg1); err != nil {
		t.Fatal(err)
	}
	var seed [32]byte
	seed[0] = 0x9
	params := &core.Msg2SessionParams{TagLen: 16, SessionNonceSeed: seed}
	msg2, srvKeys, err := responder.ConstructMsg2(params)
	if err != nil {
		t.Fatal(err)
	}
	_, cliKeys, err := initiator.ProcessMsg2(msg2)
	if err != nil {
		t.Fatal(err)
	}
	return cliKeys, srvKeys
}

// deliver replicates the daemon's inbound record/v1 path for one packet against
// a peer's route-token table / sessions. Returns the delivered user payload,
// nil for pad-only keepalives, or an error.
func deliver(table *routeTokenTable, wire []byte) ([]byte, error) {
	entry, ok := table.lookup(wire[:16])
	if !ok {
		return nil, fmt.Errorf("route token not found")
	}
	_, seq, plaintext, err := recordOpen(entry.Sess, wire)
	if err != nil {
		return nil, err
	}
	if entry.Sess.recvTokenWindow != nil {
		entry.Sess.recvTokenWindow.Observe(seq)
	}
	res := entry.Sess.handleRecordFrame(plaintext, time.Now())
	if !res.ok {
		return nil, nil
	}
	return res.payload, nil
}

func recordOpen(sess *Session, wire []byte) ([16]byte, uint64, []byte, error) {
	return recordv1.Open(sess.recvRecordKeys, sess.recvReplay, wire)
}

func sealTestData(t *testing.T, sess *Session, pn uint64, inner []byte) []byte {
	t.Helper()
	frames := makeTransportFrames(inner, maxTransportPlaintext)
	if len(frames) != 1 {
		t.Fatalf("test packet unexpectedly fragmented into %d frames", len(frames))
	}
	wire, err := sealTransportFrame(sess, pn, frames[0], transportPadLen(len(frames[0]), sess.paddingMode))
	if err != nil {
		t.Fatalf("seal %d: %v", pn, err)
	}
	return wire
}

// TestSessionStreamPast2048 streams far more than 2048 transport packets through
// the server receive path. Under the old fixed-2048-tag scheme this went dark
// after packet 2047; the sliding window must carry it.
func TestSessionStreamPast2048(t *testing.T) {
	cPriv, _, _ := core.GenerateElligatorKeypair()
	sPriv, _, _ := core.GenerateElligatorKeypair()
	kNet := bytes.Repeat([]byte{0x44}, 32)
	nid := core.DeriveNID("integ-net", "light")

	cliKeys, srvKeys := runHandshake(t, cPriv, sPriv, kNet, nid)

	table := newRouteTokenTable()
	peer := &Peer{PublicKey: []byte{0xAB}}
	sess := establishSession(table, peer, srvKeys, false, time.Unix(1000, 0))
	peer.Promote(sess, true)
	sendSess := newSession(cliKeys, true, time.Unix(1000, 0))

	const total = 5000
	var pn uint64
	for ; pn < total; pn++ {
		inner := []byte(fmt.Sprintf("packet-%d-payload", pn))
		wire := sealTestData(t, sendSess, pn, inner)
		got, err := deliver(table, wire)
		if err != nil {
			t.Fatalf("packet %d: %v", pn, err)
		}
		if !bytes.Equal(got, inner) {
			t.Fatalf("payload mismatch at %d", pn)
		}
	}

	// Keepalive: empty inner payload round-trips and delivers zero bytes.
	ka := sealTestData(t, sendSess, pn, nil)
	got, err := deliver(table, ka)
	if err != nil {
		t.Fatalf("keepalive: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("keepalive should carry no payload, got %d bytes", len(got))
	}
}

// TestRekeyGracePeriod verifies that after a rekey both the old (previous) and
// new (current) sessions decrypt, and that the previous session's tags are
// evicted once it ages past rejectAfterTime.
func TestRekeyGracePeriod(t *testing.T) {
	cPriv, _, _ := core.GenerateElligatorKeypair()
	sPriv, _, _ := core.GenerateElligatorKeypair()
	kNet := bytes.Repeat([]byte{0x55}, 32)
	nid := core.DeriveNID("rekey-net", "light")

	table := newRouteTokenTable()
	peer := &Peer{PublicKey: []byte{0xCD}}

	// First epoch.
	cli1, srv1 := runHandshake(t, cPriv, sPriv, kNet, nid)
	base := time.Unix(1000, 0)
	sess1 := establishSession(table, peer, srv1, false, base)
	peer.Promote(sess1, true)
	send1 := newSession(cli1, true, base)

	// Send one packet under epoch 1.
	w1 := sealTestData(t, send1, 0, []byte("epoch1-a"))
	if got, err := deliver(table, w1); err != nil || string(got) != "epoch1-a" {
		t.Fatalf("epoch1 packet: got=%q err=%v", got, err)
	}

	// Rekey: second epoch, promoted as current (sess1 becomes previous).
	cli2, srv2 := runHandshake(t, cPriv, sPriv, kNet, nid)
	sess2 := establishSession(table, peer, srv2, false, base)
	peer.Promote(sess2, true)
	send2 := newSession(cli2, true, base)

	if peer.Current() != sess2 || peer.previous != sess1 {
		t.Fatal("promotion did not set current=sess2, previous=sess1")
	}

	// During grace: an in-flight old-epoch packet still decrypts...
	w1b := sealTestData(t, send1, 1, []byte("epoch1-b"))
	if got, err := deliver(table, w1b); err != nil || string(got) != "epoch1-b" {
		t.Fatalf("in-flight epoch1 packet must still decode: got=%q err=%v", got, err)
	}
	// ...and a new-epoch packet decrypts too.
	w2 := sealTestData(t, send2, 0, []byte("epoch2-a"))
	if got, err := deliver(table, w2); err != nil || string(got) != "epoch2-a" {
		t.Fatalf("epoch2 packet: got=%q err=%v", got, err)
	}

	// Age the previous session out; its tags must be evicted.
	peer.ExpirePrevious(base.Add(rejectAfterTime + time.Second))
	if peer.previous != nil {
		t.Fatal("previous session should have been expired")
	}
	w1c := sealTestData(t, send1, 2, []byte("epoch1-c"))
	if _, err := deliver(table, w1c); err == nil {
		t.Fatal("old-epoch packet must be dropped after previous session expiry")
	}
	// New epoch still fine.
	w2b := sealTestData(t, send2, 1, []byte("epoch2-b"))
	if got, err := deliver(table, w2b); err != nil || string(got) != "epoch2-b" {
		t.Fatalf("epoch2 packet after expiry: got=%q err=%v", got, err)
	}
}
