package transport

import (
	"bytes"
	"testing"
)

func testKeys() *TransportKeys {
	return &TransportKeys{
		KTagRecv:       bytes.Repeat([]byte{0x22}, 32),
		SessionContext: bytes.Repeat([]byte{0x33}, 32),
	}
}

func newTestWindow(table *TagTable, peerCtx interface{}, keys *TransportKeys) *RecvWindow {
	return NewRecvWindow(peerCtx, nil, keys, table)
}

func tagPresent(table *TagTable, keys *TransportKeys, n uint64) bool {
	tag := DeriveTag(keys.KTagRecv, n, keys.SessionContext, 16)
	_, ok := table.Lookup(tag)
	return ok
}

func TestRecvWindowInitialInstall(t *testing.T) {
	keys := testKeys()
	table := NewTagTable()
	peer := "peer1"
	newTestWindow(table, peer, keys)

	if !tagPresent(table, keys, 0) || !tagPresent(table, keys, tagWindowFuture-1) {
		t.Fatal("initial window should install [0, tagWindowFuture)")
	}
	if tagPresent(table, keys, tagWindowFuture) {
		t.Fatal("tag beyond initial window should not be installed yet")
	}
}

func TestRecvWindowReplay(t *testing.T) {
	keys := testKeys()
	table := NewTagTable()
	peer := "peer1"
	rw := newTestWindow(table, peer, keys)

	if !rw.Commit(0) {
		t.Fatal("first accept of 0 must succeed")
	}
	if rw.Commit(0) {
		t.Fatal("replay of 0 must be rejected")
	}
	if !rw.Commit(5) {
		t.Fatal("fresh 5 must be accepted")
	}
	if !rw.Commit(3) {
		t.Fatal("out-of-order fresh 3 must be accepted")
	}
	if rw.Commit(3) {
		t.Fatal("replay of 3 must be rejected")
	}
}

func TestRecvWindowSlide(t *testing.T) {
	keys := testKeys()
	table := NewTagTable()
	peer := "peer1"
	rw := newTestWindow(table, peer, keys)

	maxSeen := uint64(tagWindowPast + tagSlideBatch)
	if !rw.Commit(maxSeen) {
		t.Fatalf("accept %d", maxSeen)
	}
	if !tagPresent(table, keys, maxSeen) {
		t.Fatal("tag for maxSeen must be present after slide")
	}
	if !tagPresent(table, keys, maxSeen+tagWindowFuture-1) {
		t.Fatal("future tags must be installed ahead of maxSeen")
	}
	if tagPresent(table, keys, 100) {
		t.Fatal("stale tag 100 should have been evicted")
	}
}

func TestRecvWindowTooOld(t *testing.T) {
	keys := testKeys()
	table := NewTagTable()
	peer := "peer1"
	rw := newTestWindow(table, peer, keys)

	if !rw.Commit(20000) {
		t.Fatal("accept 20000")
	}
	if rw.Commit(20000 - replayBits) {
		t.Fatal("packet older than the replay window must be rejected")
	}
	if rw.PreCheck(20000 - replayBits) {
		t.Fatal("PreCheck must also reject too-old packets")
	}
}

func TestRecvWindowTeardown(t *testing.T) {
	keys := testKeys()
	table := NewTagTable()
	peer := "peer1"
	rw := newTestWindow(table, peer, keys)

	if !tagPresent(table, keys, 0) {
		t.Fatal("tag 0 should be installed")
	}
	rw.Teardown()
	if tagPresent(table, keys, 0) {
		t.Fatal("Teardown must remove all tags")
	}
}
