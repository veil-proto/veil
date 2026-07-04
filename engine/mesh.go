package engine

// Mesh milestone-1: MESH_INTRO frame construction/parsing, hole-punch
// attempt logic, and the hub relay decision. See docs/spec/VEIL-MESH-1.md
// for the full design (byte layout rationale, hole-punch parameters, relay
// gating) — this file implements exactly what that document specifies.

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"

	"github.com/veil-proto/veil/config"

	"golang.org/x/crypto/curve25519"
)

// meshIntroMagic identifies a compact MESH_INTRO control payload carried
// inside a record/v1 CONTROL inner frame.
var meshIntroMagic = [4]byte{'V', 'M', 'I', '1'}

const (
	// meshIntroHeaderLen is the fixed portion of a MESH_INTRO frame (every
	// field up to and including allowed_ip_count), before the variable-length
	// allowed_ips list. See VEIL-MESH-1.md §3.3 for the field-by-field layout.
	meshIntroHeaderLen = 4 + 32 + 1 + 16 + 2 + 1 // = 56

	// meshAllowedIPEntryLen is one AllowedIPs entry: 4-byte IPv4 address + 1
	// byte prefix length. IPv6 AllowedIPs are out of scope for milestone-1
	// (VEIL-MESH-1.md §3.5).
	meshAllowedIPEntryLen = 5

	// maxMeshAllowedIPs bounds allowed_ip_count so a malformed/hostile count
	// byte can't make parsing read past a sane frame size.
	maxMeshAllowedIPs = 8

	// meshIntroTrailerLen is window_seconds, which follows the allowed_ips list.
	meshIntroTrailerLen = 2

	meshAddrFamilyIPv4 = 0x04
	meshAddrFamilyIPv6 = 0x06
)

// meshHolePunchWindow is the rendezvous attempt window milestone-1's hub
// always advertises in window_seconds (VEIL-MESH-1.md §3.3/§4.2): ~5
// attempts spaced meshHolePunchInterval apart.
const meshHolePunchWindow = 3 * time.Second

// meshHolePunchAttempts / meshHolePunchInterval are the concrete hole-punch
// parameters from VEIL-MESH-1.md §4.2: 5 attempts, 600ms apart (5*600ms=3s,
// matching meshHolePunchWindow).
const (
	meshHolePunchAttempts = 5
	meshHolePunchInterval = 600 * time.Millisecond
)

// meshAllowedIP is one parsed AllowedIPs entry from a MESH_INTRO frame.
type meshAllowedIP struct {
	ip     net.IP // 4-byte IPv4
	prefix int
}

// meshIntro is the parsed form of a MESH_INTRO frame.
type meshIntro struct {
	peerPubKey [32]byte
	addr       *net.UDPAddr
	allowedIPs []meshAllowedIP
	window     time.Duration
}

// encodeMeshIntro builds one MESH_INTRO frame introducing the peer at
// (pubKey, addr, allowedIPs) with a rendezvous window of window. Only IPv4
// AllowedIPs entries are encoded (non-IPv4 CIDRs are silently skipped, up to
// maxMeshAllowedIPs); see VEIL-MESH-1.md §3.5.
func encodeMeshIntro(pubKey []byte, addr *net.UDPAddr, allowedIPs []string, window time.Duration) ([]byte, error) {
	if len(pubKey) != 32 {
		return nil, errors.New("mesh intro: peer public key must be 32 bytes")
	}
	if addr == nil {
		return nil, errors.New("mesh intro: addr must not be nil")
	}

	var entries [][5]byte
	for _, cidr := range allowedIPs {
		if len(entries) >= maxMeshAllowedIPs {
			break
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue // IPv6 — out of scope for milestone-1, see §3.5
		}
		ones, _ := ipnet.Mask.Size()
		var e [5]byte
		copy(e[0:4], ip4)
		e[4] = byte(ones)
		entries = append(entries, e)
	}

	family := byte(meshAddrFamilyIPv4)
	var addrBytes [16]byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		copy(addrBytes[0:4], ip4)
	} else if ip16 := addr.IP.To16(); ip16 != nil {
		family = meshAddrFamilyIPv6
		copy(addrBytes[:], ip16)
	} else {
		return nil, errors.New("mesh intro: addr has no usable IP")
	}

	total := meshIntroHeaderLen + len(entries)*meshAllowedIPEntryLen + meshIntroTrailerLen
	frame := make([]byte, total)
	copy(frame[0:4], meshIntroMagic[:])
	copy(frame[4:36], pubKey)
	frame[36] = family
	copy(frame[37:53], addrBytes[:])
	binary.BigEndian.PutUint16(frame[53:55], uint16(addr.Port))
	frame[55] = byte(len(entries))

	off := meshIntroHeaderLen
	for _, e := range entries {
		copy(frame[off:off+meshAllowedIPEntryLen], e[:])
		off += meshAllowedIPEntryLen
	}

	windowSecs := window / time.Second
	if windowSecs <= 0 {
		windowSecs = 1
	}
	if windowSecs > 0xFFFF {
		windowSecs = 0xFFFF
	}
	binary.BigEndian.PutUint16(frame[off:off+2], uint16(windowSecs))

	return frame, nil
}

// looksLikeMeshIntro reports whether a CONTROL payload carries MESH_INTRO.
func looksLikeMeshIntro(frame []byte) bool {
	return len(frame) >= 4 && string(frame[0:4]) == string(meshIntroMagic[:])
}

// decodeMeshIntro parses a MESH_INTRO frame produced by encodeMeshIntro.
// Any structural problem is reported as an error; callers must treat a
// parse failure as a silent drop (VEIL-INVARIANTS-1.md invariant 12), never
// a wire-visible response.
func decodeMeshIntro(frame []byte) (*meshIntro, error) {
	if len(frame) < meshIntroHeaderLen+meshIntroTrailerLen {
		return nil, errors.New("mesh intro: frame too short")
	}
	if !looksLikeMeshIntro(frame) {
		return nil, errors.New("mesh intro: bad magic")
	}

	var out meshIntro
	copy(out.peerPubKey[:], frame[4:36])

	family := frame[36]
	addrBytes := frame[37:53]
	port := binary.BigEndian.Uint16(frame[53:55])

	var ip net.IP
	switch family {
	case meshAddrFamilyIPv4:
		ip = net.IP(append([]byte(nil), addrBytes[0:4]...))
	case meshAddrFamilyIPv6:
		ip = net.IP(append([]byte(nil), addrBytes...))
	default:
		return nil, errors.New("mesh intro: unknown address family")
	}
	out.addr = &net.UDPAddr{IP: ip, Port: int(port)}

	count := int(frame[55])
	if count > maxMeshAllowedIPs {
		return nil, errors.New("mesh intro: allowed_ip_count exceeds maximum")
	}
	needed := meshIntroHeaderLen + count*meshAllowedIPEntryLen + meshIntroTrailerLen
	if len(frame) < needed {
		return nil, errors.New("mesh intro: frame too short for declared allowed_ip_count")
	}

	off := meshIntroHeaderLen
	for i := 0; i < count; i++ {
		e := frame[off : off+meshAllowedIPEntryLen]
		ip := net.IP(append([]byte(nil), e[0:4]...))
		prefix := int(e[4])
		if prefix > 32 {
			return nil, errors.New("mesh intro: invalid allowed_ip prefix length")
		}
		out.allowedIPs = append(out.allowedIPs, meshAllowedIP{ip: ip, prefix: prefix})
		off += meshAllowedIPEntryLen
	}

	windowSecs := binary.BigEndian.Uint16(frame[off : off+2])
	out.window = time.Duration(windowSecs) * time.Second

	return &out, nil
}

// allowedIPStrings renders a meshIntro's allowedIPs back into CIDR strings
// suitable for config.PeerConfig.AllowedIPs.
func (mi *meshIntro) allowedIPStrings() []string {
	if len(mi.allowedIPs) == 0 {
		return nil
	}
	out := make([]string, 0, len(mi.allowedIPs))
	for _, a := range mi.allowedIPs {
		out = append(out, (&net.IPNet{IP: a.ip, Mask: net.CIDRMask(a.prefix, 32)}).String())
	}
	return out
}

// sendMeshIntro sends one MESH_INTRO frame to dst (an already-connected
// client, addressed via its own established session) introducing the peer
// identified by (introPubKey, introAddr, introAllowedIPs). Only ever called
// from hub-role code paths (see relayToPeer / the hub relay branch in
// udpToTun) — see VEIL-MESH-1.md §3.2 on why no separate authentication is
// needed: the frame is protected by dst's existing session.
func (e *Engine) sendMeshIntro(dst *Peer, introPubKey []byte, introAddr *net.UDPAddr, introAllowedIPs []string) error {
	sess := dst.SendSession()
	ep, localIP := dst.Path()
	if sess == nil || ep == nil {
		return errors.New("mesh intro: destination peer has no confirmed session")
	}
	frame, err := encodeMeshIntro(introPubKey, introAddr, introAllowedIPs, meshHolePunchWindow)
	if err != nil {
		return err
	}
	return sendControlOnSession(e.conn, sess, ep, localIP, frame, 0)
}

// handleMeshIntro processes an inbound MESH_INTRO: it registers the
// introduced peer (if not already known) and launches a bounded hole-punch
// attempt at the hub-observed address. Called from udpToTun's dispatch,
// mirroring handleMTUProbe/handleMTUProbeAck's placement (VEIL-MESH-1.md
// §3.1) — before fragment/raw-packet handling, on every engine regardless
// of hub role (a leaf receives MESH_INTRO; a hub does not — hubs don't
// introduce peers to themselves, and nothing sends them one).
func (e *Engine) handleMeshIntro(payload []byte) {
	// VEIL-MESH-1.md §3.2: a MESH_INTRO is trusted only because it arrived on
	// an already-authenticated session — that's exactly why a hub must not
	// act on one. A hub's own clients are never authorized introducers, and
	// without this check any client could send its hub (or, once P2P mesh
	// sessions exist, any other peer) a crafted MESH_INTRO-shaped frame to
	// redirect its handshake attempts at an arbitrary address, or pollute its
	// routing table with a bogus peer. The check lives here rather than at
	// the udpToTun call site so this invariant has exactly one place to
	// verify and can't be bypassed by a future call site that forgets it.
	if e.IsHub() {
		return
	}
	mi, err := decodeMeshIntro(payload)
	if err != nil {
		return // silent drop, VEIL-INVARIANTS-1.md invariant 12
	}
	// Never introduce a peer to itself, and never let a MESH_INTRO overwrite
	// this engine's own identity.
	if mi.peerPubKey == e.localPubKey() {
		return
	}

	peer := e.peerTable.GetPeer(mi.peerPubKey[:])
	if peer == nil {
		pcfg := config.PeerConfig{
			PublicKey:  append([]byte(nil), mi.peerPubKey[:]...),
			AllowedIPs: mi.allowedIPStrings(),
		}
		if err := e.AddPeer(pcfg); err != nil {
			log.Printf("mesh intro: AddPeer failed: %v", err)
			return
		}
		peer = e.peerTable.GetPeer(mi.peerPubKey[:])
		if peer == nil {
			return
		}
	}

	// Point the peer at the hub-observed endpoint so the existing initiator
	// handshake path (startInitiatorHandshake) sends there, then attempt the
	// bounded hole-punch window. Run in the background: handleMeshIntro is
	// called from the udpToTun hot loop and must not block it.
	peer.SetPath(mi.addr, nil)
	window := mi.window
	if window <= 0 {
		window = meshHolePunchWindow
	}
	go e.attemptHolePunch(peer, window)
}

// localPubKey derives this engine's own static public key from its private
// key, for the self-introduction guard in handleMeshIntro.
func (e *Engine) localPubKey() [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &e.localPriv)
	return pub
}

// attemptHolePunch drives the bounded simultaneous-open hole-punch window
// described in VEIL-MESH-1.md §4.2: up to meshHolePunchAttempts fresh Msg1
// sends, meshHolePunchInterval apart, stopping early the moment peer already
// has a confirmed session (either this attempt's own ProcessMsg2, handled by
// the ordinary handleHandshake dispatch in the udpToTun loop, or the peer's
// own inbound Msg1 completing the handshake from the other side first).
func (e *Engine) attemptHolePunch(peer *Peer, window time.Duration) {
	deadline := time.Now().Add(window)
	attempts := meshHolePunchAttempts
	interval := meshHolePunchInterval

	for i := 0; i < attempts; i++ {
		if peer.SendSession() != nil {
			return // already confirmed, e.g. the other side's Msg1 got here first
		}
		if time.Now().After(deadline) {
			return
		}
		e.startInitiatorHandshake(peer, time.Now())
		if i < attempts-1 {
			time.Sleep(interval)
		}
	}
	// No confirmation within the window: peer stays on hub relay fallback
	// (VEIL-MESH-1.md §4.5) — not a failure state, nothing further to do.
}

// relayToPeer forwards an already-decrypted inner packet to target,
// re-encrypting it under target's own session. Used only by the hub relay
// branch in udpToTun (VEIL-MESH-1.md §5.3), gated to IsHub() by the caller.
// relayToPeer forwards an already-decrypted inner packet to target,
// re-encrypting it under target's own session. Used only by the hub relay
// branch in udpToTun (VEIL-MESH-1.md §5.3), gated to IsHub() by the caller.
//
// P0.2 (VEIL-Combined-Roadmap.md): this used to have its own raw-passthrough
// fast path for inner packets at or under budget — the same bug as P0.1 in
// tunToUDP (see engine.go). Routing every relayed packet through
// makeTransportFrames, exactly like the direct-send path, means there is
// exactly one encoder for transport plaintext, used everywhere it's produced.
func (e *Engine) relayToPeer(target *Peer, inner []byte) {
	sess := target.SendSession()
	ep, localIP := target.Path()
	if sess == nil || ep == nil {
		return // target not reachable yet — silent drop, same as a routing miss
	}
	for _, frame := range makeTransportFrames(inner, target.FrameBudget()) {
		if err := transportSend(e.conn, sess, ep, localIP, frame); err != nil {
			log.Printf("mesh relay send error: %v", err)
			return
		}
	}
}

// transportSend encrypts and sends one frame on sess, mirroring the
// single-frame send path sendOnSession already uses per-frame internally.
func transportSend(conn *udpConn, sess *Session, ep *net.UDPAddr, localIP net.IP, frame []byte) error {
	pn := sess.nextPN()
	enc, err := sealTransportFrame(sess, pn, frame, transportPadLen(len(frame), sess.paddingMode))
	if err != nil {
		return err
	}
	if _, err := conn.writeTo(enc, ep, localIP); err != nil {
		return err
	}
	sess.markSent(time.Now())
	return nil
}
