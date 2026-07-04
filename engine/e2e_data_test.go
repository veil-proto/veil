package engine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/veil-proto/veil/config"
	"github.com/veil-proto/veil/core"

	"golang.org/x/crypto/curve25519"
)

var errClosedRecordingTun = errors.New("recordingTun: closed")

// recordingTun is a Tun that can be primed with a single packet to return
// from one ReadBatch call (simulating one outbound packet from the OS) and
// that captures every packet handed to WriteBatch (simulating delivery to
// the OS). Used to drive a real Engine.Run over real loopback UDP sockets —
// unlike deliver() in integration_test.go, this exercises the actual
// udpToTun/tunToUDP hot loops, not just the record/v1 seal/open primitives.
type recordingTun struct {
	toRead  chan []byte
	closed  chan struct{}
	mu      sync.Mutex
	written [][]byte
}

func newRecordingTun() *recordingTun {
	return &recordingTun{toRead: make(chan []byte, 4), closed: make(chan struct{})}
}

func (f *recordingTun) ReadBatch(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-f.toRead:
		n := copy(bufs[0], pkt)
		sizes[0] = n
		return 1, nil
	case <-f.closed:
		return 0, errClosedRecordingTun
	}
}

func (f *recordingTun) WriteBatch(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	for _, b := range bufs {
		cp := append([]byte(nil), b[offset:]...)
		f.written = append(f.written, cp)
	}
	f.mu.Unlock()
	return len(bufs), nil
}

func (f *recordingTun) BatchSize() int { return 1 }
func (f *recordingTun) Name() string   { return "rectun0" }
func (f *recordingTun) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *recordingTun) lastWritten() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.written) == 0 {
		return nil
	}
	return f.written[len(f.written)-1]
}

// buildTestIPv4Packet constructs a minimal (not checksum-valid, but
// structurally valid enough for ExtractDstIP/version-nibble sniffing) IPv4
// packet with the given destination and a recognizable payload, so a
// round-trip can assert on exact byte content.
func buildTestIPv4Packet(dst net.IP, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // version 4, IHL 5
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

// TestEngineDataPlaneEndToEnd_UnfragmentedPacketSurvivesTunWrite is a
// regression guard for the "handshake succeeds but no traffic actually
// flows" bug: record/v1's Open (record/v1/record.go) decrypts via
// aead.Open(nil, ...), which allocates a fresh buffer for the plaintext
// rather than reusing the UDP read buffer's backing array the way the old
// transport.DecapsulateTransport did. udpToTun's "full == nil" fast path
// used to just reslice the original (still-encrypted) UDP read buffer,
// assuming the decrypted bytes had landed there — after the record/v1
// switch they hadn't, so every unfragmented data packet delivered to the
// TUN device was still-encrypted garbage instead of the real payload. This
// test drives two real Engines over real loopback UDP sockets through a
// full handshake and one data packet, and asserts the receiving side's TUN
// gets the exact original bytes — unlike integration_test.go's deliver()
// helper, which calls handleRecordFrame directly and never exercises this
// code path at all.
func TestEngineDataPlaneEndToEnd_UnfragmentedPacketSurvivesTunWrite(t *testing.T) {
	cPriv, cPub, err := generateTestX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sPriv, sPub, err := generateTestX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	nid := bytes.Repeat([]byte{0x10}, 32)
	kNet := bytes.Repeat([]byte{0x20}, 32)

	serverTun := newRecordingTun()
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("server ListenUDP: %v", err)
	}
	defer serverConn.Close()
	defer serverTun.Close()

	serverCfg := &config.Config{
		Interface: config.InterfaceConfig{PrivateKey: sPriv[:], NID: nid, NetSecret: kNet},
		Peers:     []config.PeerConfig{{PublicKey: cPub[:]}},
	}
	serverEng, err := New(serverCfg, serverTun, serverConn)
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	serverErrCh := make(chan error, 4)
	serverEng.Run(context.Background(), serverErrCh)
	defer func() { serverEng.Close(); serverTun.Close(); serverConn.Close(); serverEng.Wait() }()

	clientTun := newRecordingTun()
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	defer clientConn.Close()
	defer clientTun.Close()

	const testDstCIDR = "10.9.7.0/24"
	testDstIP := net.IPv4(10, 9, 7, 42)

	clientCfg := &config.Config{
		Interface: config.InterfaceConfig{PrivateKey: cPriv[:], NID: nid, NetSecret: kNet},
		Peers: []config.PeerConfig{{
			PublicKey:  sPub[:],
			Endpoint:   serverConn.LocalAddr().String(),
			AllowedIPs: []string{testDstCIDR},
		}},
	}
	clientEng, err := New(clientCfg, clientTun, clientConn)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	clientErrCh := make(chan error, 4)
	clientEng.Run(context.Background(), clientErrCh)
	defer func() { clientEng.Close(); clientTun.Close(); clientConn.Close(); clientEng.Wait() }()

	clientPeer := clientEng.peerTable.GetPeer(sPub[:])
	if clientPeer == nil {
		t.Fatal("client peer table missing server peer")
	}
	clientEng.startInitiatorHandshake(clientPeer, time.Now())

	deadline := time.Now().Add(5 * time.Second)
	for clientPeer.SendSession() == nil {
		if time.Now().After(deadline) {
			t.Fatal("handshake did not complete within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := "GET / HTTP/1.1 test payload distinguishable from ciphertext"
	pkt := buildTestIPv4Packet(testDstIP, payload)
	clientTun.toRead <- pkt

	deadline = time.Now().Add(5 * time.Second)
	var got []byte
	for {
		got = serverTun.lastWritten()
		if got != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server TUN never received the data packet within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !bytes.Equal(got, pkt) {
		t.Fatalf("server TUN received corrupted/wrong packet:\n got  (%d bytes) = %x\n want (%d bytes) = %x", len(got), got, len(pkt), pkt)
	}
}

func generateTestX25519KeyPair() (priv, pub [32]byte, err error) {
	p, _, err := core.GenerateElligatorKeypair()
	if err != nil {
		return priv, pub, err
	}
	priv = p
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], pubBytes)
	return priv, pub, nil
}
