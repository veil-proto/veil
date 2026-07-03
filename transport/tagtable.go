package transport

import (
	"sync"
)

type TagTable struct {
	mu   sync.RWMutex
	tags map[tagKey]TagEntry
}

type tagKey [16]byte

type TagEntry struct {
	PeerCtx      interface{}
	SessionCtx   interface{}
	PacketNumber uint64
}

func NewTagTable() *TagTable {
	return &TagTable{
		tags: make(map[tagKey]TagEntry),
	}
}

func (t *TagTable) AddTag(tag []byte, peerCtx interface{}, sessionCtx interface{}, packetNumber uint64) {
	key, ok := makeTagKey(tag)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tags[key] = TagEntry{
		PeerCtx:      peerCtx,
		SessionCtx:   sessionCtx,
		PacketNumber: packetNumber,
	}
}

func (t *TagTable) Lookup(tag []byte) (TagEntry, bool) {
	key, ok := makeTagKey(tag)
	if !ok {
		return TagEntry{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	entry, ok := t.tags[key]
	return entry, ok
}

func (t *TagTable) RemoveTag(tag []byte) {
	key, ok := makeTagKey(tag)
	if !ok {
		return
	}
	t.removeKey(key)
}

func (t *TagTable) removeKey(key tagKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tags, key)
}

func makeTagKey(tag []byte) (tagKey, bool) {
	if len(tag) < len(tagKey{}) {
		return tagKey{}, false
	}
	var key tagKey
	copy(key[:], tag[:len(key)])
	return key, true
}

// Tag installation and eviction are driven by each peer's RecvWindow, which
// keeps a bounded sliding set of future/past tags in this table so a session
// never runs out of tags (see recvwindow.go).
