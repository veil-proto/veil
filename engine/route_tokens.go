package engine

import (
	"crypto/sha256"
	"sync"

	recordv1 "github.com/veil-proto/veil/record/v1"
	"github.com/veil-proto/veil/tokens"
	"github.com/veil-proto/veil/transport"
)

const (
	routeTokenSlotSpan    = 512
	routeTokenFutureSlots = 4
	routeTokenPastSlots   = 2
)

type routeTokenEntry struct {
	Peer *Peer
	Sess *Session
}

type routeTokenTable struct {
	mu     sync.RWMutex
	tokens map[[16]byte]routeTokenEntry
}

func newRouteTokenTable() *routeTokenTable {
	return &routeTokenTable{tokens: make(map[[16]byte]routeTokenEntry)}
}

func (t *routeTokenTable) add(token [16]byte, peer *Peer, sess *Session) {
	t.mu.Lock()
	t.tokens[token] = routeTokenEntry{Peer: peer, Sess: sess}
	t.mu.Unlock()
}

func (t *routeTokenTable) remove(token [16]byte, sess *Session) {
	t.mu.Lock()
	if ent, ok := t.tokens[token]; ok && ent.Sess == sess {
		delete(t.tokens, token)
	}
	t.mu.Unlock()
}

func (t *routeTokenTable) lookup(token []byte) (routeTokenEntry, bool) {
	if len(token) < 16 {
		return routeTokenEntry{}, false
	}
	var key [16]byte
	copy(key[:], token[:16])
	t.mu.RLock()
	ent, ok := t.tokens[key]
	t.mu.RUnlock()
	return ent, ok
}

type routeTokenWindow struct {
	mu        sync.Mutex
	table     *routeTokenTable
	peer      *Peer
	sess      *Session
	key       []byte
	direction tokens.Direction
	installed map[uint64][16]byte
	maxSlot   uint64
	started   bool
}

func newRouteTokenWindow(table *routeTokenTable, peer *Peer, sess *Session, key []byte, direction tokens.Direction) *routeTokenWindow {
	w := &routeTokenWindow{
		table:     table,
		peer:      peer,
		sess:      sess,
		key:       append([]byte(nil), key...),
		direction: direction,
		installed: make(map[uint64][16]byte),
	}
	w.install(0, routeTokenFutureSlots+1)
	return w
}

func (w *routeTokenWindow) Teardown() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, tok := range w.installed {
		w.table.remove(tok, w.sess)
	}
	w.installed = make(map[uint64][16]byte)
}

func (w *routeTokenWindow) Observe(seq uint64) {
	slot := routeTokenSlot(seq)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.started || slot > w.maxSlot {
		w.started = true
		w.maxSlot = slot
	}
	var from uint64
	if w.maxSlot > routeTokenPastSlots {
		from = w.maxSlot - routeTokenPastSlots
	}
	to := w.maxSlot + routeTokenFutureSlots + 1
	w.install(from, to)
	for s, tok := range w.installed {
		if s < from || s >= to {
			w.table.remove(tok, w.sess)
			delete(w.installed, s)
		}
	}
}

func (w *routeTokenWindow) install(from, to uint64) {
	for slot := from; slot < to; slot++ {
		if _, ok := w.installed[slot]; ok {
			continue
		}
		tok := tokens.Route(w.key, 0, 0, slot, w.direction)
		w.table.add(tok, w.peer, w.sess)
		w.installed[slot] = tok
	}
}

func routeTokenSlot(seq uint64) uint64 { return seq / routeTokenSlotSpan }

func routeTokenForSend(sess *Session, seq uint64) [16]byte {
	return tokens.Route(sess.sendRouteKey, 0, 0, routeTokenSlot(seq), sess.sendDirection)
}

func sendDirection(isInitiator bool) tokens.Direction {
	if isInitiator {
		return tokens.DirectionC2S
	}
	return tokens.DirectionS2C
}

func recvDirection(isInitiator bool) tokens.Direction {
	if isInitiator {
		return tokens.DirectionS2C
	}
	return tokens.DirectionC2S
}

func recordKeys(keys *transport.TransportKeys, isInitiator bool, send bool) (recordv1.DirectionKeys, []byte, tokens.Direction) {
	var keyMaterial []byte
	var tagMaterial []byte
	direction := sendDirection(isInitiator)
	if send {
		keyMaterial = keys.KSend
		tagMaterial = keys.KTagSend
	} else {
		keyMaterial = keys.KRecv
		tagMaterial = keys.KTagRecv
		direction = recvDirection(isInitiator)
	}

	var out recordv1.DirectionKeys
	copy(out.AEADKey[:], keyMaterial)
	out.RecordContext = append([]byte(nil), keys.SessionContext...)

	routeKey := deriveRecordKey("VEIL-RECORD-1 route token", tagMaterial, keys.SessionContext, direction)
	hpKey := deriveRecordKey("VEIL-RECORD-1 header protection", tagMaterial, keys.SessionContext, direction)
	nonceKey := deriveRecordKey("VEIL-RECORD-1 nonce prefix", keyMaterial, keys.NonceSeed, direction)
	copy(out.HPKey[:], hpKey)
	copy(out.NoncePrefix[:], nonceKey[:4])
	return out, routeKey, direction
}

func deriveRecordKey(label string, key, context []byte, direction tokens.Direction) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{byte(direction)})
	h.Write(key)
	h.Write(context)
	return h.Sum(nil)
}
