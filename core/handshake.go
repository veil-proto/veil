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

// Msg1 is now split across two separately-encrypted payloads (P0.3,
// VEIL-Combined-Roadmap.md): Msg1StaticPayload (the claimed initiator static
// public key, encrypted under a key only an ephemeral-static DH term
// requires) and Msg1AuthPayload (timestamp/nonce/params, encrypted under a
// key that requires the claimed static private key — see
// HandshakeMachine.ProcessMsg1's doc comment for why this ordering matters).
// Splitting them means the responder cannot even decrypt the timestamp,
// let alone act on it, without the sender having proven static-key
// possession first.

// Msg1StaticPayload carries only the initiator's claimed static public key.
type Msg1StaticPayload struct {
	CPub [32]byte
}

func (m *Msg1StaticPayload) Encode() []byte {
	out := make([]byte, 32)
	copy(out, m.CPub[:])
	return out
}

func DecodeMsg1StaticPayload(data []byte) (*Msg1StaticPayload, error) {
	if len(data) != 32 {
		return nil, errors.New("invalid Msg1StaticPayload size")
	}
	var m Msg1StaticPayload
	copy(m.CPub[:], data)
	return &m, nil
}

// Msg1AuthPayload carries everything that must not be trusted (in
// particular, must not be allowed to mutate any peer state) until the sender
// has proven possession of the static private key matching the pubkey
// claimed in Msg1StaticPayload.
type Msg1AuthPayload struct {
	Timestamp               [12]byte
	ClientNonce             [16]byte
	RequestedTagLen         byte
	RequestedPaddingProfile byte
	Reserved                [22]byte
}

func (m *Msg1AuthPayload) Encode() []byte {
	out := make([]byte, 52)
	copy(out[0:12], m.Timestamp[:])
	copy(out[12:28], m.ClientNonce[:])
	out[28] = m.RequestedTagLen
	out[29] = m.RequestedPaddingProfile
	copy(out[30:52], m.Reserved[:])
	return out
}

func DecodeMsg1AuthPayload(data []byte) (*Msg1AuthPayload, error) {
	if len(data) != 52 {
		return nil, errors.New("invalid Msg1AuthPayload size")
	}
	var m Msg1AuthPayload
	copy(m.Timestamp[:], data[0:12])
	copy(m.ClientNonce[:], data[12:28])
	m.RequestedTagLen = data[28]
	m.RequestedPaddingProfile = data[29]
	copy(m.Reserved[:], data[30:52])
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
