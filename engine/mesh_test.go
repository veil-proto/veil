package engine

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/veil-proto/veil/config"
)

// TestMeshIntro_RoundTrip verifies encodeMeshIntro/decodeMeshIntro reproduce
// the same peer pubkey, endpoint, AllowedIPs and window across the wire,
// mirroring fragment_test.go's round-trip style for VFR1.
func TestMeshIntro_RoundTrip(t *testing.T) {
	pub := bytes.Repeat([]byte{0xAB}, 32)
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51820}
	allowed := []string{"10.9.0.5/32", "10.9.1.0/24"}
	window := 3 * time.Second

	frame, err := encodeMeshIntro(pub, addr, allowed, window)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	if !looksLikeMeshIntro(frame) {
		t.Fatal("encoded frame does not carry the MESH_INTRO magic prefix")
	}

	got, err := decodeMeshIntro(frame)
	if err != nil {
		t.Fatalf("decodeMeshIntro: %v", err)
	}
	if !bytes.Equal(got.peerPubKey[:], pub) {
		t.Errorf("peerPubKey mismatch: got %x want %x", got.peerPubKey[:], pub)
	}
	if got.addr.Port != addr.Port || !got.addr.IP.Equal(addr.IP) {
		t.Errorf("addr mismatch: got %v want %v", got.addr, addr)
	}
	if got.window != window {
		t.Errorf("window mismatch: got %v want %v", got.window, window)
	}
	gotIPs := got.allowedIPStrings()
	if len(gotIPs) != len(allowed) {
		t.Fatalf("allowedIPs count mismatch: got %v want %v", gotIPs, allowed)
	}
	for i, want := range allowed {
		if gotIPs[i] != want {
			t.Errorf("allowedIPs[%d]: got %q want %q", i, gotIPs[i], want)
		}
	}
}

// TestMeshIntro_RoundTripIPv6Endpoint verifies an IPv6 hub-observed endpoint
// survives encode/decode even though AllowedIPs stays IPv4-only (VEIL-MESH-1
// §3.5: IPv6 AllowedIPs entries are out of scope for milestone-1, but an
// IPv6 endpoint address must still round-trip).
func TestMeshIntro_RoundTripIPv6Endpoint(t *testing.T) {
	pub := bytes.Repeat([]byte{0xCD}, 32)
	addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345}

	frame, err := encodeMeshIntro(pub, addr, nil, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	got, err := decodeMeshIntro(frame)
	if err != nil {
		t.Fatalf("decodeMeshIntro: %v", err)
	}
	if !got.addr.IP.Equal(addr.IP) {
		t.Errorf("IPv6 addr mismatch: got %v want %v", got.addr.IP, addr.IP)
	}
	if len(got.allowedIPs) != 0 {
		t.Errorf("expected no allowedIPs, got %v", got.allowedIPs)
	}
}

// TestMeshIntro_NoAllowedIPs verifies the zero-AllowedIPs case (an
// introduced peer with nothing routable yet) round-trips cleanly.
func TestMeshIntro_NoAllowedIPs(t *testing.T) {
	pub := bytes.Repeat([]byte{0x11}, 32)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4000}

	frame, err := encodeMeshIntro(pub, addr, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	got, err := decodeMeshIntro(frame)
	if err != nil {
		t.Fatalf("decodeMeshIntro: %v", err)
	}
	if len(got.allowedIPs) != 0 {
		t.Fatalf("expected zero allowedIPs, got %d", len(got.allowedIPs))
	}
}

// TestMeshIntro_IPv6AllowedIPsSkipped verifies non-IPv4 CIDRs are silently
// skipped rather than corrupting the frame (VEIL-MESH-1.md §3.5).
func TestMeshIntro_IPv6AllowedIPsSkipped(t *testing.T) {
	pub := bytes.Repeat([]byte{0x22}, 32)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 3), Port: 4001}

	frame, err := encodeMeshIntro(pub, addr, []string{"2001:db8::/32", "10.0.0.0/8"}, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	got, err := decodeMeshIntro(frame)
	if err != nil {
		t.Fatalf("decodeMeshIntro: %v", err)
	}
	want := []string{"10.0.0.0/8"}
	gotIPs := got.allowedIPStrings()
	if len(gotIPs) != len(want) || gotIPs[0] != want[0] {
		t.Fatalf("expected only the IPv4 CIDR to survive: got %v want %v", gotIPs, want)
	}
}

// TestMeshIntro_TooManyAllowedIPsClamped verifies encode never emits more
// than maxMeshAllowedIPs entries even if given more.
func TestMeshIntro_TooManyAllowedIPsClamped(t *testing.T) {
	pub := bytes.Repeat([]byte{0x33}, 32)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 4), Port: 4002}

	var many []string
	for i := 0; i < maxMeshAllowedIPs+5; i++ {
		many = append(many, "10.0.0.0/8")
	}

	frame, err := encodeMeshIntro(pub, addr, many, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	got, err := decodeMeshIntro(frame)
	if err != nil {
		t.Fatalf("decodeMeshIntro: %v", err)
	}
	if len(got.allowedIPs) != maxMeshAllowedIPs {
		t.Fatalf("expected clamp to %d entries, got %d", maxMeshAllowedIPs, len(got.allowedIPs))
	}
}

// TestMeshIntro_DecodeRejectsTruncatedFrame verifies a short/malformed
// frame is rejected rather than read out of bounds — the parse-failure path
// callers must treat as a silent drop (VEIL-INVARIANTS-1.md invariant 12).
func TestMeshIntro_DecodeRejectsTruncatedFrame(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		meshIntroMagic[:],
		append(append([]byte{}, meshIntroMagic[:]...), bytes.Repeat([]byte{0}, 10)...),
	}
	for i, frame := range cases {
		if _, err := decodeMeshIntro(frame); err == nil {
			t.Errorf("case %d: expected decode error for truncated frame %x", i, frame)
		}
	}
}

// TestMeshIntro_DecodeRejectsOversizedAllowedIPCount verifies a
// declared-but-not-actually-present allowed_ip_count is rejected instead of
// reading past the buffer.
func TestMeshIntro_DecodeRejectsOversizedAllowedIPCount(t *testing.T) {
	pub := bytes.Repeat([]byte{0x44}, 32)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 5), Port: 4003}
	frame, err := encodeMeshIntro(pub, addr, nil, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	// Lie about allowed_ip_count without actually growing the frame.
	frame[55] = maxMeshAllowedIPs
	if _, err := decodeMeshIntro(frame); err == nil {
		t.Fatal("expected decode error for allowed_ip_count exceeding actual frame length")
	}
}

// TestMeshIntro_DecodeRejectsBadMagic verifies a frame with the right shape
// but wrong magic is rejected (so it isn't confused with VFR1/VPR1/VPA1).
func TestMeshIntro_DecodeRejectsBadMagic(t *testing.T) {
	pub := bytes.Repeat([]byte{0x55}, 32)
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 6), Port: 4004}
	frame, err := encodeMeshIntro(pub, addr, nil, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}
	copy(frame[0:4], fragmentMagic[:])
	if _, err := decodeMeshIntro(frame); err == nil {
		t.Fatal("expected decode error for non-MESH_INTRO magic")
	}
}

// ---- hub relay routing decision ----

// TestHubRelay_ForwardsToOtherPeer verifies the forward-vs-deliver-locally
// decision described in VEIL-MESH-1.md §5.2: a destination IP owned by a
// peer other than the packet's sender must resolve to that other peer
// (forward), not the sender itself.
func TestHubRelay_ForwardsToOtherPeer(t *testing.T) {
	sender := &Peer{PublicKey: []byte("sender")}
	other := &Peer{PublicKey: []byte("other")}

	rt := NewRoutingTable()
	rt.AddRoute(mustCIDR(t, "10.9.0.1/32"), sender)
	rt.AddRoute(mustCIDR(t, "10.9.0.2/32"), other)

	dst := net.ParseIP("10.9.0.2")
	target := rt.Lookup(dst)
	if target != other {
		t.Fatalf("expected lookup to resolve to other peer, got %q", peerName(target))
	}
	if target == sender {
		t.Fatal("must not resolve to the sender itself")
	}
}

// TestHubRelay_NoForwardToSelf verifies a packet whose destination resolves
// back to the sending peer itself must NOT be treated as relay traffic (this
// is the "target != j.peer" guard in udpToTun) — e.g. the sender's own
// AllowedIPs range, or a keepalive/echo scenario.
func TestHubRelay_NoForwardToSelf(t *testing.T) {
	sender := &Peer{PublicKey: []byte("sender")}

	rt := NewRoutingTable()
	rt.AddRoute(mustCIDR(t, "10.9.0.0/24"), sender)

	dst := net.ParseIP("10.9.0.9")
	target := rt.Lookup(dst)
	if target != sender {
		t.Fatalf("expected lookup to resolve to sender, got %q", peerName(target))
	}
	// The udpToTun guard is `target != nil && target != j.peer`; here
	// target == sender (== j.peer in the real loop), so relay must not fire.
	if target != sender {
		t.Fatal("relay guard would incorrectly fire for traffic addressed back to the sender")
	}
}

// TestHubRelay_NoRouteMeansLocalDelivery verifies a destination with no
// matching route (e.g. the hub's own tunnel address) falls through to local
// TUN delivery exactly as it does today on a non-mesh deployment.
func TestHubRelay_NoRouteMeansLocalDelivery(t *testing.T) {
	sender := &Peer{PublicKey: []byte("sender")}
	rt := NewRoutingTable()
	rt.AddRoute(mustCIDR(t, "10.9.0.1/32"), sender)

	dst := net.ParseIP("10.8.0.1") // the hub's own address, never routed
	if target := rt.Lookup(dst); target != nil {
		t.Fatalf("expected no route (local delivery), got %q", peerName(target))
	}
}

// TestEngine_HubIgnoresInboundMeshIntro verifies VEIL-MESH-1.md §3.2's stated
// invariant: "a hub itself ignores an inbound MESH_INTRO from one of its
// clients". A MESH_INTRO is trusted only because it arrived on an
// already-authenticated session — without this check, any authenticated
// client of a hub (or, once P2P mesh sessions exist, any peer at all) could
// send a crafted MESH_INTRO-shaped frame to make the receiver add an
// arbitrary peer/route and fire handshake attempts at an attacker-chosen
// address. This calls handleMeshIntro directly (as udpToTun's dispatch
// does) with the engine in hub role and asserts it is a complete no-op.
func TestEngine_HubIgnoresInboundMeshIntro(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()
	eng.EnableMeshHub()

	introPub := bytes.Repeat([]byte{0x99}, 32)
	introAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 60), Port: 51820}
	frame, err := encodeMeshIntro(introPub, introAddr, []string{"10.9.4.0/24"}, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}

	before := len(eng.peerTable.GetAllPeers())
	eng.handleMeshIntro(frame)
	after := len(eng.peerTable.GetAllPeers())
	if before != after {
		t.Fatal("hub-role engine must not process an inbound MESH_INTRO (VEIL-MESH-1.md §3.2)")
	}
	if eng.peerTable.GetPeer(introPub) != nil {
		t.Fatal("hub-role engine must not register a peer from an inbound MESH_INTRO")
	}
	if eng.routingTable.Lookup(net.ParseIP("10.9.4.5")) != nil {
		t.Fatal("hub-role engine must not install a route from an inbound MESH_INTRO")
	}
}

// ---- Engine hub role plumbing ----

// TestEngine_MeshHubRoleToggle verifies EnableMeshHub/DisableMeshHub/IsHub
// behave as a simple runtime flag, off by default so leaf engines never
// carry relay behavior unless explicitly opted in.
func TestEngine_MeshHubRoleToggle(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	if eng.IsHub() {
		t.Fatal("engine must not be a hub by default")
	}
	eng.EnableMeshHub()
	if !eng.IsHub() {
		t.Fatal("IsHub() must be true after EnableMeshHub()")
	}
	eng.DisableMeshHub()
	if eng.IsHub() {
		t.Fatal("IsHub() must be false after DisableMeshHub()")
	}
}

// TestEngine_HandleMeshIntroAddsPeer verifies a hub-signed MESH_INTRO frame
// (as delivered by handleMeshIntro) registers the introduced peer via the
// existing Engine.AddPeer path, including its AllowedIPs routes — the
// "register the introduced peer if not already known" half of
// VEIL-MESH-1.md §4.2 step 1, tested without a real UDP network by calling
// handleMeshIntro directly against a decoded frame's payload.
func TestEngine_HandleMeshIntroAddsPeer(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	introPub := bytes.Repeat([]byte{0x77}, 32)
	introAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 50), Port: 51820}
	frame, err := encodeMeshIntro(introPub, introAddr, []string{"10.9.2.0/24"}, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}

	eng.handleMeshIntro(frame)

	// AddPeer + the resulting hole-punch attempt goroutine race, but the peer
	// registration itself (AddPeer) happens synchronously inside
	// handleMeshIntro before the goroutine is launched, so this is safe to
	// assert immediately.
	p := eng.peerTable.GetPeer(introPub)
	if p == nil {
		t.Fatal("expected introduced peer to be registered in the peer table")
	}
	if got := eng.routingTable.Lookup(net.ParseIP("10.9.2.5")); got != p {
		t.Fatal("expected AllowedIPs route to be installed for the introduced peer")
	}
}

// TestEngine_HandleMeshIntroIgnoresSelf verifies a MESH_INTRO that (by bug or
// malice) names this engine's own static public key is dropped rather than
// self-registered.
func TestEngine_HandleMeshIntroIgnoresSelf(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	self := eng.localPubKey()
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 51), Port: 51821}
	frame, err := encodeMeshIntro(self[:], addr, nil, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}

	eng.handleMeshIntro(frame)

	if eng.peerTable.GetPeer(self[:]) != nil {
		t.Fatal("engine must not register a peer entry for its own public key")
	}
}

// TestEngine_HandleMeshIntroMalformedIsSilentlyDropped verifies a malformed
// MESH_INTRO payload (e.g. arriving from handleTransportFrame's dispatch
// with the right magic but corrupt body) does not panic and adds no peer.
func TestEngine_HandleMeshIntroMalformedIsSilentlyDropped(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	before := len(eng.peerTable.GetAllPeers())
	eng.handleMeshIntro(append(append([]byte{}, meshIntroMagic[:]...), 0, 1, 2))
	after := len(eng.peerTable.GetAllPeers())
	if before != after {
		t.Fatalf("malformed MESH_INTRO must not add a peer: before=%d after=%d", before, after)
	}
}

// TestEngine_HandleMeshIntroPeerAlreadyKnown verifies re-introducing an
// already-registered peer does not error out or duplicate it (AddPeer
// itself rejects duplicates; handleMeshIntro must tolerate that and just use
// the existing peer).
func TestEngine_HandleMeshIntroPeerAlreadyKnown(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	pub := bytes.Repeat([]byte{0x88}, 32)
	if err := eng.AddPeer(config.PeerConfig{PublicKey: pub, AllowedIPs: []string{"10.9.3.0/24"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 52), Port: 51822}
	frame, err := encodeMeshIntro(pub, addr, []string{"10.9.3.0/24"}, time.Second)
	if err != nil {
		t.Fatalf("encodeMeshIntro: %v", err)
	}

	eng.handleMeshIntro(frame)

	peers := eng.peerTable.GetAllPeers()
	count := 0
	for _, p := range peers {
		if bytes.Equal(p.PublicKey, pub) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one peer entry for the already-known key, got %d", count)
	}
}
