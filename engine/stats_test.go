package engine

import (
	"net"
	"testing"
	"time"
)

func TestStatsSnapshot(t *testing.T) {
	e := &Engine{peerTable: NewPeerTable()}
	p := &Peer{PublicKey: []byte{0xde, 0xad, 0xbe, 0xef}}
	p.SetEndpoint(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 51820})
	p.SetFrameBudget(1358)
	p.addTx(1200)
	p.addTx(800)
	p.addRx(500)
	p.markRecv(time.Now())
	// A confirmed current session makes the peer report Connected.
	sess := newSession(testTransportKeys(0x30), true, time.Now())
	sess.markConfirmed()
	p.Promote(sess, true)
	e.peerTable.AddPeer(p)

	stats := e.Stats()
	if len(stats) != 1 {
		t.Fatalf("got %d peer stats, want 1", len(stats))
	}
	s := stats[0]
	if s.PublicKey != "deadbeef" {
		t.Errorf("PublicKey = %q, want deadbeef", s.PublicKey)
	}
	if s.TxBytes != 2000 || s.TxPackets != 2 {
		t.Errorf("tx = %d bytes / %d pkts, want 2000/2", s.TxBytes, s.TxPackets)
	}
	if s.RxBytes != 500 || s.RxPackets != 1 {
		t.Errorf("rx = %d bytes / %d pkts, want 500/1", s.RxBytes, s.RxPackets)
	}
	if s.FrameBudget != 1358 {
		t.Errorf("FrameBudget = %d, want 1358", s.FrameBudget)
	}
	if s.Endpoint != "203.0.113.5:51820" {
		t.Errorf("Endpoint = %q", s.Endpoint)
	}
	if !s.Connected {
		t.Errorf("expected Connected = true")
	}
	if s.LastHandshake.IsZero() {
		t.Errorf("expected non-zero LastHandshake")
	}
}

func TestStatsDisconnectedWhenSilent(t *testing.T) {
	e := &Engine{peerTable: NewPeerTable()}
	p := &Peer{PublicKey: []byte{0x01}}
	sess := newSession(testTransportKeys(0x40), true, time.Now().Add(-10*time.Minute))
	sess.markConfirmed()
	p.Promote(sess, true)
	p.markRecv(time.Now().Add(-watchdogTimeout - time.Minute)) // silent
	e.peerTable.AddPeer(p)

	if e.Stats()[0].Connected {
		t.Errorf("silent peer should report Connected = false")
	}
}
