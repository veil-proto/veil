// Package tokens implements the VEIL-TOKENS-1 token ladder.
package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

type Direction byte

const (
	DirectionC2S Direction = 1
	DirectionS2C Direction = 2
)

type State byte

const (
	StatePrevious State = 1
	StateCurrent  State = 2
	StateNext     State = 3
)

type Entry struct {
	Token   [16]byte
	State   State
	Expires time.Time
}

type Window struct {
	mu     sync.RWMutex
	tokens map[[16]byte]Entry
}

func Rendezvous(secret, serverID []byte, timeBucket uint64, peerHint []byte) [16]byte {
	m := hmac.New(sha256.New, secret)
	m.Write(serverID)
	var b [8]byte
	binary.BigEndian.PutUint64(b[0:8], timeBucket)
	m.Write(b[:])
	m.Write(peerHint)
	return first16(m.Sum(nil))
}

func Route(key []byte, epochID, pathID, tokenSlot uint64, direction Direction) [16]byte {
	m := hmac.New(sha256.New, key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[0:8], epochID)
	m.Write(b[:])
	binary.BigEndian.PutUint64(b[0:8], pathID)
	m.Write(b[:])
	binary.BigEndian.PutUint64(b[0:8], tokenSlot)
	m.Write(b[:])
	m.Write([]byte{byte(direction)})
	return first16(m.Sum(nil))
}

func Path(key []byte, endpointFamily byte, pathID, epochID uint64) [16]byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte{endpointFamily})
	var b [8]byte
	binary.BigEndian.PutUint64(b[0:8], pathID)
	m.Write(b[:])
	binary.BigEndian.PutUint64(b[0:8], epochID)
	m.Write(b[:])
	return first16(m.Sum(nil))
}

func NewWindow() *Window {
	return &Window{tokens: make(map[[16]byte]Entry)}
}

func (w *Window) Install(token [16]byte, state State, expires time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tokens == nil {
		w.tokens = make(map[[16]byte]Entry)
	}
	w.tokens[token] = Entry{Token: token, State: state, Expires: expires}
}

func (w *Window) Lookup(token [16]byte, now time.Time) (Entry, bool) {
	w.mu.RLock()
	ent, ok := w.tokens[token]
	w.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if !ent.Expires.IsZero() && !now.Before(ent.Expires) {
		w.mu.Lock()
		delete(w.tokens, token)
		w.mu.Unlock()
		return Entry{}, false
	}
	return ent, true
}

func (w *Window) Promote(now time.Time, previousTTL time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for tok, ent := range w.tokens {
		switch ent.State {
		case StateCurrent:
			ent.State = StatePrevious
			ent.Expires = now.Add(previousTTL)
			w.tokens[tok] = ent
		case StateNext:
			ent.State = StateCurrent
			w.tokens[tok] = ent
		}
	}
}

func (w *Window) Expire(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for tok, ent := range w.tokens {
		if !ent.Expires.IsZero() && !now.Before(ent.Expires) {
			delete(w.tokens, tok)
		}
	}
}

func first16(in []byte) [16]byte {
	var out [16]byte
	copy(out[:], in)
	return out
}
