package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// blake2sHash is a helper to satisfy the hash.Hash requirement for HKDF.
func blake2sHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

func GenerateX25519KeyPair() (priv, pub [32]byte, err error) {
	_, err = io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func HKDFBlake2s(secret, salt, info []byte, outLen int) ([]byte, error) {
	kdf := hkdf.New(blake2sHash, secret, salt, info)
	out := make([]byte, outLen)
	_, err := io.ReadFull(kdf, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Msg1Payload previously carried an 8-byte PskID field. Nothing ever consumed
// it (the PSK, when configured, is a single fixed per-peer secret known to
// both sides out of band — there is no multi-PSK selection to hint at), so it
// was dead ceremonial wire surface. Removed in favor of Reserved to keep the
// wire size and all downstream offset math in ConstructMsg1/ProcessMsg1
// unchanged.
type Msg1Payload struct {
	CPub                    [32]byte
	Timestamp               [12]byte
	ClientNonce             [16]byte
	RequestedTagLen         byte
	RequestedPaddingProfile byte
	Reserved                [22]byte
}

func (m *Msg1Payload) Encode() []byte {
	out := make([]byte, 84)
	copy(out[0:32], m.CPub[:])
	copy(out[32:44], m.Timestamp[:])
	copy(out[44:60], m.ClientNonce[:])
	out[60] = m.RequestedTagLen
	out[61] = m.RequestedPaddingProfile
	copy(out[62:84], m.Reserved[:])
	return out
}

func DecodeMsg1Payload(data []byte) (*Msg1Payload, error) {
	if len(data) != 84 {
		return nil, errors.New("invalid Msg1Payload size")
	}
	var m Msg1Payload
	copy(m.CPub[:], data[0:32])
	copy(m.Timestamp[:], data[32:44])
	copy(m.ClientNonce[:], data[44:60])
	m.RequestedTagLen = data[60]
	m.RequestedPaddingProfile = data[61]
	copy(m.Reserved[:], data[62:84])
	return &m, nil
}

// EncodeMonotonicTimestamp fills the 12-byte handshake timestamp field with
// the current time in nanoseconds since the Unix epoch (first 8 bytes,
// big-endian; the trailing 4 bytes are reserved and left zero). Used as an
// anti-replay counter: the responder rejects any Msg1 from a given peer whose
// timestamp doesn't strictly exceed the last one it accepted, so a captured
// handshake message can't be replayed later to elicit a second response from
// the server. Ordinary comparison (CompareTimestamps) is enough because the
// value only needs to be monotonic, not secret.
func EncodeMonotonicTimestamp() [12]byte {
	var ts [12]byte
	binary.BigEndian.PutUint64(ts[:8], uint64(time.Now().UnixNano()))
	return ts
}

// CompareTimestamps reports whether a is strictly newer than b.
func CompareTimestamps(a, b [12]byte) bool {
	return binary.BigEndian.Uint64(a[:8]) > binary.BigEndian.Uint64(b[:8])
}

// NOTE: the standalone Msg1 constructor that used to live here has been removed.
// It carried a raw X25519 public key on the wire (the pre-v0.3 format) and was
// superseded by HandshakeMachine.ConstructMsg1, which ships an Elligator2
// representative instead. All handshake construction now goes through the
// HandshakeMachine so there is a single, consistent wire format.
