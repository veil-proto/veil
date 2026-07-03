package engine

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/veil-proto/veil/core"
	"github.com/veil-proto/veil/transport"
)

// TestTransportStateMachineFuzzing fuzzes the Transport phase (TagTable and ReplayWindow)
// against network anomalies: reorder, loss, duplicates, and cryptographically invalid packets.
func TestTransportStateMachineFuzzing(t *testing.T) {
	cPriv, _, _ := core.GenerateElligatorKeypair()
	sPriv, _, _ := core.GenerateElligatorKeypair()
	kNet := bytes.Repeat([]byte{0x44}, 32)
	nid := core.DeriveNID("integ-net", "light")

	cliKeys, srvKeys := runHandshake(t, cPriv, sPriv, kNet, nid)

	table := transport.NewTagTable()
	peer := &Peer{PublicKey: []byte{0xAB}}
	sess := establishSession(table, peer, srvKeys, false, time.Unix(1000, 0))
	peer.Promote(sess, true)

	const totalPackets = 3000
	type testPacket struct {
		pn    uint64
		inner []byte
		wire  []byte
	}
	var packets []testPacket

	for pn := uint64(0); pn < totalPackets; pn++ {
		inner := []byte(fmt.Sprintf("fuzz-payload-%d", pn))
		wire, err := transport.EncapsulateTransport(cliKeys, pn, inner, 0, 16)
		if err != nil {
			t.Fatalf("encap %d: %v", pn, err)
		}
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
	// TagTable default window is 512, so packet 521 should still be within the precomputed window.
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
	// Modifying the MAC of packet 522 should cause DecapsulateTransport to fail,
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
	// Jump beyond the receive tag window. The exact window is a transport
	// tuning constant; what matters here is that the table is bounded.
	jump := 522 + 2048 + 1
	_, err = deliver(table, packets[jump].wire)
	if err == nil {
		t.Fatalf("Expected jump beyond the receive tag window to fail TagTable lookup!")
	}
}

// TestTagTableCollision guarantees that TagTable doesn't panic or incorrectly route
// when tags naturally collide (which is astronomically unlikely with 16 bytes, but we simulate it).
func TestTagTableCollision(t *testing.T) {
	table := transport.NewTagTable()

	fakeTag := bytes.Repeat([]byte{0xAA}, 16)

	sess1 := &Session{}
	sess2 := &Session{}
	peer1 := &Peer{}
	peer2 := &Peer{}

	// Insert first
	table.AddTag(fakeTag, peer1, sess1, 10)

	// Insert second (collision on same tag)
	table.AddTag(fakeTag, peer2, sess2, 20)

	lookup, ok := table.Lookup(fakeTag)
	if !ok {
		t.Fatalf("Expected tag to be found")
	}
	if lookup.PacketNumber != 20 {
		t.Fatalf("Expected overwritten entry")
	}
}
