package engine

// Engine is the OS-independent VEIL data plane. It owns the peer/tag/routing
// tables and runs the three hot loops (maintenance, TUN->UDP, UDP->TUN). OS
// front-ends (the Linux daemon, the Windows client) are responsible only for
// creating the TUN device and the UDP socket and for configuring interface
// addresses / routes / DNS before calling Run.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/veil-proto/veil/config"
	"github.com/veil-proto/veil/core"
	"github.com/veil-proto/veil/transport"
)

// Tun is the minimal TUN interface the data plane needs. OS front-ends (the
// per-OS client repos) provide a concrete implementation.
type Tun interface {
	ReadBatch(bufs [][]byte, sizes []int, offset int) (int, error)
	WriteBatch(bufs [][]byte, offset int) (int, error)
	BatchSize() int
	Name() string
	Close() error
}

const (
	// udpBatchSize is how many datagrams one recvmmsg/sendmmsg call moves.
	udpBatchSize = 128
	// maxPacketSize is the largest inner packet a TUN read can produce (a
	// GSO super-packet on Linux, WINTUN_MAX_IP_PACKET_SIZE on Windows).
	maxPacketSize = 65535
	// udpReadBufSize bounds one received datagram; anything longer than the
	// wire-format maximum is invalid and gets dropped during decapsulation.
	udpReadBufSize = 4096
)

var handshakePrefixes = []int{0, 4, 8, 12, 16}

// ---- peer table ----

type PeerTable struct {
	mu    sync.RWMutex
	peers map[string]*Peer
}

func NewPeerTable() *PeerTable {
	return &PeerTable{peers: make(map[string]*Peer)}
}

func (pt *PeerTable) AddPeer(peer *Peer) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.peers[hex.EncodeToString(peer.PublicKey)] = peer
}

func (pt *PeerTable) GetPeer(pubKey []byte) *Peer {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.peers[hex.EncodeToString(pubKey)]
}

func (pt *PeerTable) GetAllPeers() []*Peer {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	list := make([]*Peer, 0, len(pt.peers))
	for _, p := range pt.peers {
		list = append(list, p)
	}
	return list
}

// ---- wire-image helpers (intrinsic padding) ----

func generateRandomPrefix() []byte {
	choices := []int{0, 4, 8, 12, 16}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(choices))))
	length := choices[n.Int64()]
	if length == 0 {
		return nil
	}
	b := make([]byte, length)
	rand.Read(b)
	return b
}

// Length-padding buckets shared by every VEIL packet type, so no single
// message type has a distinct, identifiable size of its own.
var lengthBuckets = []int{192, 256, 384, 512, 768, 1024, 1280}

func randUint(n int) int {
	if n <= 0 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

func padHandshake(pkt []byte) []byte {
	target := len(pkt)
	for _, b := range lengthBuckets {
		if b >= len(pkt) {
			target = b
			break
		}
	}
	if target <= len(pkt) {
		return pkt
	}
	pad := make([]byte, target-len(pkt))
	rand.Read(pad)
	return append(pkt, pad...)
}

// padQuantum is the granularity every non-"none" padding mode rounds frame
// sizes up to. Quantizing (rather than adding purely random padding) is what
// actually hides the inner packet length: an observer only ever sees one of a
// handful of bucket sizes instead of the exact plaintext size leaking through.
const padQuantum = 128

// transportPadLen calculates data-plane padding without exceeding the outer UDP
// payload budget used by the fragmentation layer.
//
//   - "none" (and legacy empty): no padding — the frame's size still directly
//     reveals the inner packet size. Only for benchmarking / debugging.
//   - "light" (the default): quantize the frame up to the next padQuantum
//     boundary, so the exact inner length is masked to 128-byte granularity at
//     negligible overhead (≤127 bytes, usually far less).
//   - anything stronger (e.g. "medium"/"heavy"): the same quantization plus up
//     to a full quantum of extra random jitter, so even the bucket boundary is
//     not a reliable signal.
//
// Every result is clamped so the padded frame never exceeds maxOuterPayload.
func transportPadLen(innerLen int, modes ...string) uint16 {
	mode := "light"
	if len(modes) > 0 && modes[0] != "" {
		mode = modes[0]
	}
	if mode == "none" {
		return 0
	}

	// plaintextLen is what DecapsulateTransport measures the padding against:
	// the inner packet plus the 2-byte pad_len trailer. Quantize that so the
	// observable ciphertext length lands on a fixed grid.
	plaintextLen := innerLen + 2
	pad := 0
	if rem := plaintextLen % padQuantum; rem != 0 {
		pad = padQuantum - rem
	}
	if mode != "light" {
		pad += randUint(padQuantum)
	}

	maxPad := maxOuterPayload - transportOverhead - innerLen
	if maxPad <= 0 {
		return 0
	}
	if pad > maxPad {
		pad = maxPad
	}
	return uint16(pad)
}

// ---- session helpers ----

func establishSession(tagTable *transport.TagTable, peer *Peer, keys *transport.TransportKeys, isInitiator bool, now time.Time) *Session {
	paddingMode := "light"
	if peer.IfaceCfg != nil {
		paddingMode = peer.IfaceCfg.Padding
	}
	sess := newSession(keys, isInitiator, now, paddingMode)
	sess.recv = transport.NewRecvWindow(peer, sess, keys, tagTable)
	return sess
}

func sendOnSession(conn *udpConn, endpoint *net.UDPAddr, localIP net.IP, peer *Peer, sess *Session, inner []byte) error {
	for _, frame := range makeTransportFrames(inner, peer.FrameBudget()) {
		pn := sess.nextPN()
		enc, err := transport.EncapsulateTransport(sess.keys, pn, frame, transportPadLen(len(frame), sess.paddingMode), 16)
		if err != nil {
			return err
		}
		if _, err = conn.writeTo(enc, endpoint, localIP); err != nil {
			return err
		}
		sess.markSent(time.Now())
	}
	return nil
}

func keepaliveInterval() time.Duration {
	base := keepaliveDefault
	jitter := base / 5
	return base - jitter + time.Duration(randUint(int(2*jitter)))
}

// ---- Engine ----

type Engine struct {
	cfg          *config.Config
	tun          Tun
	conn         *udpConn
	peerTable    *PeerTable
	routingTable *RoutingTable
	tagTable     *transport.TagTable
	localPriv    [32]byte
}

// New builds an Engine from a parsed config, a ready TUN device and a bound UDP
// socket. Interface addressing / routing / DNS must already be configured by the
// caller (that part is OS-specific).
func New(cfg *config.Config, tunDev Tun, conn *net.UDPConn) (*Engine, error) {
	e := &Engine{
		cfg:          cfg,
		tun:          tunDev,
		conn:         newUDPConn(conn),
		peerTable:    NewPeerTable(),
		routingTable: NewRoutingTable(),
		tagTable:     transport.NewTagTable(),
	}
	copy(e.localPriv[:], cfg.Interface.PrivateKey)

	for _, pcfg := range cfg.Peers {
		var endpointAddr *net.UDPAddr
		if pcfg.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", pcfg.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("resolve endpoint %s: %w", pcfg.Endpoint, err)
			}
			endpointAddr = addr
		}

		var remotePub [32]byte
		copy(remotePub[:], pcfg.PublicKey)

		peer := &Peer{
			PublicKey:   pcfg.PublicKey,
			IfaceCfg:    &cfg.Interface,
			localPriv:   e.localPriv,
			remotePub:   remotePub,
			nid:         cfg.Interface.NID,
			kNet:        cfg.Interface.NetSecret,
			isInitiator: endpointAddr != nil,
			endpoint:    endpointAddr,
		}
		e.peerTable.AddPeer(peer)

		for _, allowedIP := range pcfg.AllowedIPs {
			if _, ipnet, err := net.ParseCIDR(allowedIP); err == nil {
				e.routingTable.AddRoute(ipnet, peer)
				log.Printf("Added route %s -> Peer %x", allowedIP, pcfg.PublicKey[:4])
			}
		}
	}
	return e, nil
}

// Run launches the data-plane goroutines and blocks until a loop reports a fatal
// error on errChan.
func (e *Engine) Run(errChan chan error) {
	go e.maintenanceLoop()
	go e.tunToUDP(errChan)
	go e.udpToTun(errChan)
}

func (e *Engine) maintenanceLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		for _, peer := range e.peerTable.GetAllPeers() {
			peer.ExpirePrevious(now)
			cur := peer.Current()
			ep := peer.Endpoint()

			if peer.isInitiator && ep != nil {
				// Rekey on age, or force a fresh handshake if the tunnel went
				// silent: we're still sending keepalives but nothing has come
				// back for watchdogTimeout, so the session is a black hole and
				// waiting out rekeyAfterTime (~30 min) would strand the client.
				silent := tunnelSilent(cur, peer.LastRecv(), now)
				need := cur == nil || cur.age(now) > rekeyAfterTime || silent
				if need {
					if _, lastInit := peer.Pending(); now.Sub(lastInit) >= rekeyTimeout {
						if silent {
							log.Printf("Peer %x silent for >%s, forcing handshake", peer.PublicKey[:4], watchdogTimeout)
						}
						e.startInitiatorHandshake(peer, now)
					}
				}
			}

			// Keepalive on the session we actually send on, so the peer keeps
			// seeing traffic (and, during a rekey, so the responder confirms the
			// new session promptly).
			sendSess := peer.SendSession()
			if sendSess != nil && ep != nil && sendSess.age(now) <= rejectAfterTime {
				if now.Sub(sendSess.lastSent()) >= keepaliveInterval() {
					if err := sendOnSession(e.conn, ep, peer.LocalIP(), peer, sendSess, nil); err != nil {
						log.Printf("keepalive send error: %v", err)
					}
				}

				// Periodically re-check the path MTU so a path that shrank
				// mid-session (roaming, route flap) is caught and the budget
				// pulled down, instead of black-holing full-size frames until
				// the next rekey. updateMTU also re-attempts to grow if the path
				// improved.
				if now.Sub(peer.lastMTUCheck()) >= pmtuRefreshInterval {
					peer.setLastMTUCheck(now)
					e.launchMTUUpdate(peer)
				}
			}
		}
	}
}

// udpWriteJob is one staged-but-not-yet-encrypted frame. The packet number is
// assigned at stage time (appendFrame), in the same order as today, so
// reordering the actual AEAD work in flush changes nothing about what goes on
// the wire — only when the CPU work for it happens.
type udpWriteJob struct {
	sess   *Session
	pn     uint64
	frame  []byte
	padLen uint16
}

// udpWriteBatch accumulates frames to encrypt and flushes them with one
// batched send, so the TUN->UDP path performs no per-packet allocations and
// (on Linux) one sendmmsg per batch. Encryption itself happens in flush,
// parallelized across cores for large batches (see parallel.go) — safe here
// specifically because every frame in a batch is already collected before any
// of them are sealed, so results just land back at the index they were given.
type udpWriteBatch struct {
	conn *udpConn
	jobs []udpWriteJob
	pkts [][]byte
	eps  []*net.UDPAddr
	srcs []net.IP
	bufs [][]byte // persistent backing storage for pkts
	n    int
}

func newUDPWriteBatch(conn *udpConn) *udpWriteBatch {
	b := &udpWriteBatch{
		conn: conn,
		jobs: make([]udpWriteJob, udpBatchSize),
		pkts: make([][]byte, udpBatchSize),
		eps:  make([]*net.UDPAddr, udpBatchSize),
		srcs: make([]net.IP, udpBatchSize),
		bufs: make([][]byte, udpBatchSize),
	}
	for i := range b.bufs {
		b.bufs[i] = make([]byte, 0, maxOuterPayload+64)
	}
	return b
}

func (b *udpWriteBatch) appendFrame(sess *Session, frame []byte, ep *net.UDPAddr, src net.IP) {
	b.jobs[b.n] = udpWriteJob{
		sess:   sess,
		pn:     sess.nextPN(),
		frame:  frame,
		padLen: transportPadLen(len(frame), sess.paddingMode),
	}
	b.eps[b.n] = ep
	b.srcs[b.n] = src
	b.n++
	if b.n == len(b.jobs) {
		b.flush()
	}
}

func (b *udpWriteBatch) flush() {
	if b.n == 0 {
		return
	}
	n := b.n
	parallelRange(n, func(i int) {
		j := &b.jobs[i]
		enc, err := transport.EncapsulateTransportInto(b.bufs[i], j.sess.keys, j.pn, j.frame, j.padLen, 16)
		if err != nil {
			log.Printf("encapsulate error: %v", err)
			b.pkts[i] = nil
			return
		}
		b.pkts[i] = enc
	})

	// Compact out any encryption failures (rare — only if AEAD setup itself
	// errors) before handing the batch to the socket layer, which assumes
	// every entry is a real packet.
	w := 0
	for r := 0; r < n; r++ {
		if b.pkts[r] == nil {
			continue
		}
		if w != r {
			b.pkts[w], b.eps[w], b.srcs[w] = b.pkts[r], b.eps[r], b.srcs[r]
		}
		w++
	}
	if w > 0 {
		if err := b.conn.writeBatch(b.pkts[:w], b.eps[:w], b.srcs[:w]); err != nil {
			log.Printf("UDP send error: %v", err)
		}
	}
	b.n = 0
}

func (e *Engine) tunToUDP(errChan chan error) {
	batch := e.tun.BatchSize()
	if batch < 1 {
		batch = 1
	}
	readBufs := make([][]byte, batch)
	for i := range readBufs {
		readBufs[i] = make([]byte, maxPacketSize)
	}
	sizes := make([]int, batch)
	out := newUDPWriteBatch(e.conn)

	debugTiming := os.Getenv("VEIL_DEBUG_TIMING") != ""
	logged := 0
	sentCount := 0
	lastSentReport := time.Now()

	for {
		readStart := time.Now()
		n, err := e.tun.ReadBatch(readBufs, sizes, 0)
		readDur := time.Since(readStart)
		if err != nil {
			errChan <- fmt.Errorf("tun read error: %w", err)
			return
		}
		now := time.Now()
		for i := 0; i < n; i++ {
			packet := readBufs[i][:sizes[i]]
			dstIP := ExtractDstIP(packet)
			if dstIP == nil {
				continue
			}
			peer := e.routingTable.Lookup(dstIP)
			if peer == nil {
				continue
			}
			budget := peer.FrameBudget()
			clampTCPMSS(packet, budget)
			ep, localIP := peer.Path()
			sess := peer.SendSession()
			if ep == nil || sess == nil || sess.age(now) > rejectAfterTime {
				continue
			}
			if len(packet) <= budget {
				out.appendFrame(sess, packet, ep, localIP)
				sentCount++
			} else {
				for _, frame := range makeTransportFrames(packet, budget) {
					out.appendFrame(sess, frame, ep, localIP)
					sentCount++
				}
			}
			peer.addTx(len(packet))
			sess.markSent(now)
		}
		flushStart := time.Now()
		out.flush()
		flushDur := time.Since(flushStart)
		if debugTiming && time.Since(lastSentReport) >= time.Second {
			log.Printf("[timing] tunToUDP sent=%d frames/sec", sentCount)
			sentCount = 0
			lastSentReport = time.Now()
		}
		if debugTiming && logged < 300 && (readDur > time.Millisecond || flushDur > time.Millisecond) {
			log.Printf("[timing] tunToUDP n=%d readDur=%v flushDur=%v", n, readDur, flushDur)
			logged++
		}
	}
}

// udpDecryptJob is one packet that passed the cheap pre-checks (tag lookup,
// replay pre-check) and is waiting on the actual AEAD open. i indexes back
// into the batch's bufs/remotes/locals for the phase-3 sequential step.
type udpDecryptJob struct {
	i      int
	sess   *Session
	peer   *Peer
	pn     uint64
	packet []byte
	out    []byte
	failed bool
}

func (e *Engine) udpToTun(errChan chan error) {
	batch := e.conn.batchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, udpReadBufSize)
	}
	sizes := make([]int, batch)
	remotes := make([]*net.UDPAddr, batch)
	locals := make([]net.IP, batch)
	tunBufs := make([][]byte, 0, batch)
	jobs := make([]udpDecryptJob, 0, batch)
	readErrs := 0

	debugTiming := os.Getenv("VEIL_DEBUG_TIMING") != ""
	var okCount, tagMiss, precheckFail, decryptFail, commitFail int
	lastReport := time.Now()

	for {
		n, err := e.conn.readBatch(bufs, sizes, remotes, locals)
		if err != nil {
			// Transient receive errors (most notably the ICMP-unreachable
			// induced WSAECONNRESET on Windows) must not kill the tunnel:
			// dropping the loop here turns one stray ICMP into total loss.
			readErrs++
			if errors.Is(err, net.ErrClosed) || readErrs > 1000 {
				errChan <- fmt.Errorf("udp read error: %w", err)
				return
			}
			continue
		}
		readErrs = 0
		now := time.Now()
		tunBufs = tunBufs[:0]

		// Phase 1 (sequential, cheap): tag lookup, handshake dispatch, and the
		// replay pre-check all touch shared per-session/per-table state, so
		// they stay in arrival order exactly as before. Anything that passes
		// becomes a job waiting on the one genuinely expensive step.
		jobs = jobs[:0]
		for i := 0; i < n; i++ {
			if sizes[i] < 16+16+2 || remotes[i] == nil {
				continue
			}
			packet := bufs[i][:sizes[i]]

			entry, ok := e.tagTable.Lookup(packet[:16])
			if !ok {
				if debugTiming {
					tagMiss++
				}
				e.handleHandshake(packet, remotes[i], locals[i])
				continue
			}

			sess, _ := entry.SessionCtx.(*Session)
			peer, _ := entry.PeerCtx.(*Peer)
			if sess == nil || sess.recv == nil {
				continue
			}
			if !sess.recv.PreCheck(entry.PacketNumber) {
				if debugTiming {
					precheckFail++
				}
				continue
			}
			jobs = append(jobs, udpDecryptJob{i: i, sess: sess, peer: peer, pn: entry.PacketNumber, packet: packet})
		}

		// Phase 2 (parallel): the AEAD open is a pure function of (keys, pn,
		// packet) — independent across every job in this batch — so it's the
		// one step actually worth spreading across cores. See parallel.go.
		parallelRange(len(jobs), func(k int) {
			j := &jobs[k]
			out, err := transport.DecapsulateTransport(j.sess.keys, j.pn, j.packet, 16)
			if err != nil {
				j.failed = true
				return
			}
			j.out = out
		})

		// Phase 3 (sequential): commit into the replay window in the original
		// arrival order, then everything downstream is unchanged from before.
		for k := range jobs {
			j := &jobs[k]
			if j.failed {
				if debugTiming {
					decryptFail++
				}
				continue
			}
			if !j.sess.recv.Commit(j.pn) {
				if debugTiming {
					commitFail++
				}
				continue
			}
			if debugTiming {
				okCount++
			}
			// Receiving valid data on a session proves the peer holds its keys;
			// once confirmed, the responder starts sending downstream on it.
			j.sess.markConfirmed()
			// Reset the silent-tunnel watchdog: real inbound traffic (including
			// the peer's keepalives) means this direction of the path is alive.
			j.peer.markRecv(now)
			if j.peer.NotePath(remotes[j.i], locals[j.i]) {
				log.Printf("Peer %x endpoint -> %s via local %s", j.peer.PublicKey[:4], remotes[j.i], locals[j.i])
			}

			decapsulated := j.out
			if len(decapsulated) >= 4 {
				switch string(decapsulated[:4]) {
				case string(probeMagic[:]):
					e.handleMTUProbe(decapsulated, j.sess, remotes[j.i], locals[j.i])
					continue
				case string(probeAckMagic[:]):
					handleMTUProbeAck(decapsulated, j.peer)
					continue
				}
			}

			inner, full, ok := j.sess.handleTransportFrame(decapsulated, now)
			if !ok {
				continue // keepalive or incomplete fragment
			}
			if full == nil {
				// The decrypted packet sits tagLen bytes into the UDP read
				// buffer, which doubles as the batched TUN write headroom.
				full = bufs[j.i][:tunWriteOffset+len(inner)]
			}
			j.peer.addRx(len(inner))
			tunBufs = append(tunBufs, full)
		}
		if debugTiming && time.Since(lastReport) >= time.Second {
			log.Printf("[timing] udpToTun ok=%d tagMiss=%d precheckFail=%d decryptFail=%d commitFail=%d",
				okCount, tagMiss, precheckFail, decryptFail, commitFail)
			okCount, tagMiss, precheckFail, decryptFail, commitFail = 0, 0, 0, 0, 0
			lastReport = time.Now()
		}
		if len(tunBufs) > 0 {
			if _, err := e.tun.WriteBatch(tunBufs, tunWriteOffset); err != nil {
				log.Printf("TUN write error: %v", err)
			}
		}
	}
}

func (e *Engine) startInitiatorHandshake(peer *Peer, now time.Time) {
	endpoint := peer.Endpoint()
	if endpoint == nil {
		return
	}
	hm := core.NewHandshakeMachine(true, peer.kNet, peer.nid, peer.localPriv, peer.remotePub)
	msg1, err := hm.ConstructMsg1(generateRandomPrefix())
	if err != nil {
		log.Printf("Failed to construct Msg1: %v", err)
		return
	}
	peer.SetPending(hm, now)
	if _, err := e.conn.writeTo(padHandshake(msg1), endpoint, peer.LocalIP()); err != nil {
		log.Printf("Failed to send Msg1: %v", err)
	} else {
		log.Printf("Sent Handshake Msg1 to %v", endpoint)
	}
}

func (e *Engine) handleHandshake(packet []byte, remote *net.UDPAddr, localIP net.IP) {
	now := time.Now()

	// 1) Msg2 for any initiator peer with an in-flight handshake.
	for _, p := range e.peerTable.GetAllPeers() {
		hm, _ := p.Pending()
		if hm == nil || !hm.IsInitiator {
			continue
		}
		if _, keys, _, err := hm.ProcessMsg2(packet, handshakePrefixes); err == nil {
			sess := establishSession(e.tagTable, p, keys, true, now)
			// The initiator holds the keys now, so the session is confirmed and
			// safe to send on immediately.
			p.Promote(sess, true)
			// Processing Msg2 is itself proof the peer responded — start the
			// watchdog clock so the new session isn't seen as instantly silent.
			p.markRecv(now)
			// Send a keepalive at once so the responder receives data on the new
			// session and switches its downstream traffic over without a gap.
			if ep := p.Endpoint(); ep != nil {
				if err := sendOnSession(e.conn, ep, p.LocalIP(), p, sess, nil); err != nil {
					log.Printf("rekey confirm keepalive error: %v", err)
				}
			}
			log.Printf("Initiator session established/rekeyed with %v", remote)
			e.launchMTUUpdate(p)
			return
		}
	}

	// 2) Msg1 (we are the responder).
	rhm := core.NewHandshakeMachine(false, e.cfg.Interface.NetSecret, e.cfg.Interface.NID, e.localPriv, [32]byte{})
	payload, _, err := rhm.ProcessMsg1(packet, handshakePrefixes)
	if err != nil {
		return
	}
	peer := e.peerTable.GetPeer(payload.CPub[:])
	if peer == nil {
		log.Printf("Msg1 from unconfigured client key %x", payload.CPub[:4])
		return
	}
	if !peer.CheckAndUpdateMsg1Timestamp(payload.Timestamp) {
		// Timestamp doesn't strictly exceed the last one accepted from this
		// peer: either a stale retry racing an already-processed handshake, or
		// a captured Msg1 replayed later. Drop it exactly like any other
		// invalid handshake — no response, no distinguishable behavior either
		// way.
		return
	}

	var nonceSeed [32]byte
	if _, err := rand.Read(nonceSeed[:]); err != nil {
		log.Printf("nonce seed rng error: %v", err)
		return
	}
	params := &core.Msg2SessionParams{TagLen: 16, SessionNonceSeed: nonceSeed}
	msg2, keys, err := rhm.ConstructMsg2(generateRandomPrefix(), params)
	if err != nil {
		log.Printf("ConstructMsg2 error: %v", err)
		return
	}
	if _, err := e.conn.writeTo(padHandshake(msg2), remote, localIP); err != nil {
		log.Printf("Msg2 send error: %v", err)
		return
	}
	peer.SetPath(remote, localIP)
	sess := establishSession(e.tagTable, peer, keys, false, now)
	// Responder: keep sending on the previous session until the initiator proves
	// it holds these keys by sending data on the new one (marked in udpToTun).
	peer.Promote(sess, false)
	peer.markRecv(now)
	log.Printf("Responder session established/rekeyed with %v", remote)
	e.launchMTUUpdate(peer)
}
