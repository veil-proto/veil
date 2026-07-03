package engine

import (
	"bytes"
	"fmt"
	"github.com/veil-proto/veil/transport"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/veil-proto/veil/core"
)

// runHandshake performs a full Msg1/Msg2 exchange and returns the initiator and
// responder transport keys.
func runHandshake(t *testing.T, cPriv, sPriv [32]byte, kNet, nid []byte) (cli, srv *transport.TransportKeys) {
	t.Helper()
	prefixes := []int{0, 4, 8, 12, 16}
	sPubB, _ := curve25519.X25519(sPriv[:], curve25519.Basepoint)
	var sPub [32]byte
	copy(sPub[:], sPubB)

	initiator := core.NewHandshakeMachine(true, kNet, nid, cPriv, sPub)
	responder := core.NewHandshakeMachine(false, kNet, nid, sPriv, [32]byte{})

	msg1, err := initiator.ConstructMsg1([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.ProcessMsg1(msg1, prefixes); err != nil {
		t.Fatal(err)
	}
	var seed [32]byte
	seed[0] = 0x9
	params := &core.Msg2SessionParams{TagLen: 16, SessionNonceSeed: seed}
	msg2, srvKeys, err := responder.ConstructMsg2([]byte{5, 6, 7, 8}, params)
	if err != nil {
		t.Fatal(err)
	}
	_, cliKeys, _, err := initiator.ProcessMsg2(msg2, prefixes)
	if err != nil {
		t.Fatal(err)
	}
	return cliKeys, srvKeys
}

// deliver replicates the daemon's inbound transport path for one packet against
// a peer's tag table / sessions. Returns the delivered payload, or an error.
func deliver(table *transport.TagTable, wire []byte) ([]byte, error) {
	tag := wire[:16]
	entry, ok := table.Lookup(tag)
	if !ok {
		return nil, fmt.Errorf("tag not found")
	}
	sess := entry.SessionCtx.(*Session)
	if !sess.recv.PreCheck(entry.PacketNumber) {
		return nil, fmt.Errorf("replay pre-check rejected %d", entry.PacketNumber)
	}
	got, err := transport.DecapsulateTransport(sess.keys, entry.PacketNumber, wire, 16)
	if err != nil {
		return nil, err
	}
	if !sess.recv.Commit(entry.PacketNumber) {
		return nil, fmt.Errorf("commit rejected %d", entry.PacketNumber)
	}
	return got, nil
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

	table := transport.NewTagTable()
	peer := &Peer{PublicKey: []byte{0xAB}}
	sess := establishSession(table, peer, srvKeys, false, time.Unix(1000, 0))
	peer.Promote(sess, true)

	const total = 5000
	var pn uint64
	for ; pn < total; pn++ {
		inner := []byte(fmt.Sprintf("packet-%d-payload", pn))
		wire, err := transport.EncapsulateTransport(cliKeys, pn, inner, transportPadLen(len(inner)), 16)
		if err != nil {
			t.Fatalf("encap %d: %v", pn, err)
		}
		got, err := deliver(table, wire)
		if err != nil {
			t.Fatalf("packet %d: %v", pn, err)
		}
		if !bytes.Equal(got, inner) {
			t.Fatalf("payload mismatch at %d", pn)
		}
	}

	// Keepalive: empty inner payload round-trips and delivers zero bytes.
	ka, _ := transport.EncapsulateTransport(cliKeys, pn, nil, transportPadLen(0), 16)
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

	table := transport.NewTagTable()
	peer := &Peer{PublicKey: []byte{0xCD}}

	// First epoch.
	cli1, srv1 := runHandshake(t, cPriv, sPriv, kNet, nid)
	base := time.Unix(1000, 0)
	sess1 := establishSession(table, peer, srv1, false, base)
	peer.Promote(sess1, true)

	// Send one packet under epoch 1.
	w1, _ := transport.EncapsulateTransport(cli1, 0, []byte("epoch1-a"), 0, 16)
	if got, err := deliver(table, w1); err != nil || string(got) != "epoch1-a" {
		t.Fatalf("epoch1 packet: got=%q err=%v", got, err)
	}

	// Rekey: second epoch, promoted as current (sess1 becomes previous).
	cli2, srv2 := runHandshake(t, cPriv, sPriv, kNet, nid)
	sess2 := establishSession(table, peer, srv2, false, base)
	peer.Promote(sess2, true)

	if peer.Current() != sess2 || peer.previous != sess1 {
		t.Fatal("promotion did not set current=sess2, previous=sess1")
	}

	// During grace: an in-flight old-epoch packet still decrypts...
	w1b, _ := transport.EncapsulateTransport(cli1, 1, []byte("epoch1-b"), 0, 16)
	if got, err := deliver(table, w1b); err != nil || string(got) != "epoch1-b" {
		t.Fatalf("in-flight epoch1 packet must still decode: got=%q err=%v", got, err)
	}
	// ...and a new-epoch packet decrypts too.
	w2, _ := transport.EncapsulateTransport(cli2, 0, []byte("epoch2-a"), 0, 16)
	if got, err := deliver(table, w2); err != nil || string(got) != "epoch2-a" {
		t.Fatalf("epoch2 packet: got=%q err=%v", got, err)
	}

	// Age the previous session out; its tags must be evicted.
	peer.ExpirePrevious(base.Add(rejectAfterTime + time.Second))
	if peer.previous != nil {
		t.Fatal("previous session should have been expired")
	}
	w1c, _ := transport.EncapsulateTransport(cli1, 2, []byte("epoch1-c"), 0, 16)
	if _, err := deliver(table, w1c); err == nil {
		t.Fatal("old-epoch packet must be dropped after previous session expiry")
	}
	// New epoch still fine.
	w2b, _ := transport.EncapsulateTransport(cli2, 1, []byte("epoch2-b"), 0, 16)
	if got, err := deliver(table, w2b); err != nil || string(got) != "epoch2-b" {
		t.Fatalf("epoch2 packet after expiry: got=%q err=%v", got, err)
	}
}
