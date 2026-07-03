package engine

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/veil-proto/veil/core"
)

// TestTransportStateMachineFuzzing fuzzes the record/v1 transport phase
// (route-token lookup and ReplayWindow)
// against network anomalies: reorder, loss, duplicates, and cryptographically invalid packets.
func TestTransportStateMachineFuzzing(t *testing.T) {
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

	const totalPackets = 4000
	type testPacket struct {
		pn    uint64
		inner []byte
		wire  []byte
	}
	var packets []testPacket

	for pn := uint64(0); pn < totalPackets; pn++ {
		inner := []byte(fmt.Sprintf("fuzz-payload-%d", pn))
		wire := sealTestData(t, sendSess, pn, inner)
		packets = append(packets, testPacket{pn: pn, inner: inner, wire: wire})
	}

	// 1. Basic In-Order Delivery
	for i := 0; i < 10; i++ {
		got, err := deliver(table, packets[i].wire)
		if err != nil {
			t.Fatalf("Failed basic delivery %d: %v", i, err)
		}
		if !bytes.Equal(got, packets[i].inner) {
			t.Fatalf("Payload mismatch on basic delivery %d", i)
		}
	}

	// 2. Duplicate Packets (ReplayWindow Check)
	_, err := deliver(table, packets[5].wire)
	if err == nil {
		t.Fatalf("Expected duplicate packet 5 to be rejected by ReplayWindow!")
	}

	// 3. Reordering (Packets 20 down to 11)
	for i := 20; i >= 11; i-- {
		got, err := deliver(table, packets[i].wire)
		if err != nil {
			t.Fatalf("Failed reordered delivery %d: %v", i, err)
		}
		if !bytes.Equal(got, packets[i].inner) {
			t.Fatalf("Payload mismatch on reordered delivery %d", i)
		}
	}

	// 4. Burst Loss (Skip packets 21 to 520 - 500 packets lost)
	// Route-token windows advance by bounded slots, so packet 521 should still be within the admitted window.
	got, err := deliver(table, packets[521].wire)
	if err != nil {
		t.Fatalf("Failed burst loss recovery at packet 521: %v", err)
	}
	if !bytes.Equal(got, packets[521].inner) {
		t.Fatalf("Payload mismatch at 521")
	}

	// 5. Delayed out-of-order packet (Packet 21)
	// Packet 21 is 500 packets behind the leading edge (521), but the window is 8192.
	// ReplayWindow must ACCEPT it because it was never received!
	got, err = deliver(table, packets[21].wire)
	if err != nil {
		t.Fatalf("Expected delayed packet 21 to be accepted by ReplayWindow!")
	}
	if !bytes.Equal(got, packets[21].inner) {
		t.Fatalf("Payload mismatch at 21")
	}

	// But an extremely old packet (beyond replayBits) would be rejected.
	// Since we don't want to generate 8000 packets just for this, we trust the math or write a unit test.

	// 6. Valid Tag, Invalid AEAD
	// Modifying the MAC of packet 522 should cause record/v1 open to fail,
	// and ReplayWindow MUST NOT commit the packet number!
	badWire := make([]byte, len(packets[522].wire))
	copy(badWire, packets[522].wire)
	badWire[len(badWire)-1] ^= 0xFF // Flip a bit in the Poly1305 MAC

	_, err = deliver(table, badWire)
	if err == nil {
		t.Fatalf("Expected invalid AEAD to be rejected!")
	}

	// Ensure the state didn't break. The legitimate packet 522 should still be accepted.
	got, err = deliver(table, packets[522].wire)
	if err != nil {
		t.Fatalf("Valid delivery after AEAD failure failed: %v", err)
	}
	if !bytes.Equal(got, packets[522].inner) {
		t.Fatalf("Payload mismatch at 522")
	}

	// 7. Extreme Burst Loss (Desynchronization)
	// Jump beyond the receive route-token window. The exact window is a transport
	// tuning constant; what matters here is that the table is bounded.
	jump := (1 + routeTokenFutureSlots + 1) * routeTokenSlotSpan
	_, err = deliver(table, packets[jump].wire)
	if err == nil {
		t.Fatalf("Expected jump beyond the receive route-token window to fail lookup!")
	}
}

// TestRouteTokenTableCollision guarantees that the route-token table doesn't
// panic or incorrectly route when tokens naturally collide (astronomically
// unlikely with 16 bytes, but simulated here).
func TestRouteTokenTableCollision(t *testing.T) {
	table := newRouteTokenTable()

	var fakeToken [16]byte
	copy(fakeToken[:], bytes.Repeat([]byte{0xAA}, 16))

	sess1 := &Session{}
	sess2 := &Session{}
	peer1 := &Peer{}
	peer2 := &Peer{}

	// Insert first
	table.add(fakeToken, peer1, sess1)

	// Insert second (collision on same tag)
	table.add(fakeToken, peer2, sess2)

	lookup, ok := table.lookup(fakeToken[:])
	if !ok {
		t.Fatalf("Expected token to be found")
	}
	if lookup.Peer != peer2 || lookup.Sess != sess2 {
		t.Fatalf("Expected overwritten entry")
	}
}
