package engine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/veil-proto/veil/config"
)

// fakeTun is a minimal Tun whose ReadBatch blocks until Close is called,
// mirroring how a real TUN device's blocking read behaves — this is what
// exercises the "Close() alone doesn't unblock a read; the caller must also
// close the device" contract documented on Engine.Close.
type fakeTun struct {
	closed chan struct{}
}

func newFakeTun() *fakeTun { return &fakeTun{closed: make(chan struct{})} }

func (f *fakeTun) ReadBatch(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-f.closed
	return 0, errors.New("fakeTun: closed")
}
func (f *fakeTun) WriteBatch(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (f *fakeTun) BatchSize() int                                    { return 1 }
func (f *fakeTun) Name() string                                      { return "faketun0" }
func (f *fakeTun) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func testConfig() *config.Config {
	return &config.Config{
		Interface: config.InterfaceConfig{
			PrivateKey: bytes.Repeat([]byte{0x01}, 32),
			NID:        bytes.Repeat([]byte{0x02}, 32),
			NetSecret:  bytes.Repeat([]byte{0x03}, 32),
		},
	}
}

func newTestEngine(t *testing.T) (*Engine, *fakeTun, *net.UDPConn) {
	t.Helper()
	tun := newFakeTun()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	eng, err := New(testConfig(), tun, conn)
	if err != nil {
		conn.Close()
		t.Fatalf("New: %v", err)
	}
	return eng, tun, conn
}

// TestEngineCloseWaitStopsAllLoops verifies the Close/Wait contract: after
// Close (which signals the loops) and the caller closing tun/conn (which
// unblocks their in-flight reads), Wait must return promptly, and a clean
// shutdown must not report anything on errChan.
func TestEngineCloseWaitStopsAllLoops(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	errChan := make(chan error, 2)
	eng.Run(context.Background(), errChan)

	// Let the goroutines actually start and reach their blocking reads.
	time.Sleep(20 * time.Millisecond)

	eng.Close()
	tun.Close()
	conn.Close()

	done := make(chan struct{})
	go func() {
		eng.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Engine.Wait() did not return within 2s of Close()")
	}

	select {
	case err := <-errChan:
		t.Fatalf("expected no fatal error on a clean Close/Wait shutdown, got: %v", err)
	default:
	}

	// Close must be idempotent.
	eng.Close()
}

func TestEngineAddPeerRemovePeer(t *testing.T) {
	eng, tun, conn := newTestEngine(t)
	defer conn.Close()
	defer tun.Close()

	pub := bytes.Repeat([]byte{0xAA}, 32)
	pcfg := config.PeerConfig{PublicKey: pub, AllowedIPs: []string{"10.9.0.0/24"}}

	if err := eng.AddPeer(pcfg); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if eng.peerTable.GetPeer(pub) == nil {
		t.Fatal("peer not present in peer table after AddPeer")
	}
	if p := eng.routingTable.Lookup(net.ParseIP("10.9.0.5")); p == nil {
		t.Fatal("route not installed after AddPeer")
	}

	if err := eng.AddPeer(pcfg); err == nil {
		t.Fatal("expected AddPeer of an already-registered public key to fail")
	}

	invalid := config.PeerConfig{PublicKey: []byte{0x01, 0x02}}
	if err := eng.AddPeer(invalid); err == nil {
		t.Fatal("expected AddPeer with a malformed public key to fail validation")
	}

	if err := eng.RemovePeer(pub); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if eng.peerTable.GetPeer(pub) != nil {
		t.Fatal("peer still present in peer table after RemovePeer")
	}
	if p := eng.routingTable.Lookup(net.ParseIP("10.9.0.5")); p != nil {
		t.Fatal("route still present after RemovePeer")
	}

	if err := eng.RemovePeer(pub); err == nil {
		t.Fatal("expected RemovePeer of a missing peer to fail")
	}
}

func TestEnginePopulatesKeepaliveOverrideFromConfig(t *testing.T) {
	cfg := testConfig()
	pub := bytes.Repeat([]byte{0xBB}, 32)
	cfg.Peers = []config.PeerConfig{{PublicKey: pub, PersistentKeepalive: 45}}

	tun := newFakeTun()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()
	defer tun.Close()

	eng, err := New(cfg, tun, conn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := eng.peerTable.GetPeer(pub)
	if p == nil {
		t.Fatal("configured peer missing from peer table")
	}
	if p.keepaliveOverride != 45*time.Second {
		t.Fatalf("keepaliveOverride = %v, want 45s", p.keepaliveOverride)
	}
}
