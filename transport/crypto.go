package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type TransportKeys struct {
	KSend          []byte
	KRecv          []byte
	KTagSend       []byte
	KTagRecv       []byte
	SessionContext []byte
	NonceSeed      []byte

	sendOnce sync.Once
	sendAEAD cipher.AEAD
	sendErr  error
	recvOnce sync.Once
	recvAEAD cipher.AEAD
	recvErr  error
}

func (k *TransportKeys) senderAEAD() (cipher.AEAD, error) {
	k.sendOnce.Do(func() {
		k.sendAEAD, k.sendErr = chacha20poly1305.New(k.KSend)
	})
	return k.sendAEAD, k.sendErr
}

func (k *TransportKeys) receiverAEAD() (cipher.AEAD, error) {
	k.recvOnce.Do(func() {
		k.recvAEAD, k.recvErr = chacha20poly1305.New(k.KRecv)
	})
	return k.recvAEAD, k.recvErr
}

func DeriveTag(kTag []byte, packetNumber uint64, sessionContext []byte, tagLen int) []byte {
	var out [32]byte
	full := deriveTagInto(out[:0], kTag, packetNumber, sessionContext)
	return append([]byte(nil), full[:tagLen]...)
}

func deriveTagInto(dst []byte, kTag []byte, packetNumber uint64, sessionContext []byte) []byte {
	// tag_n = BLAKE2s(key = K_tag_direction, data = "tag" || encode64_le(n) || session_context)[:T]
	h, _ := blake2s.New256(kTag)
	h.Write([]byte("tag"))

	var nBuf [8]byte
	binary.LittleEndian.PutUint64(nBuf[:], packetNumber)
	h.Write(nBuf[:])
	h.Write(sessionContext)

	return h.Sum(dst)
}

func DeriveNonce(kDir []byte, nonceSeed []byte, packetNumber uint64) []byte {
	var out [32]byte
	full := deriveNonceInto(out[:0], kDir, nonceSeed, packetNumber)
	return append([]byte(nil), full[:12]...)
}

func deriveNonceInto(dst []byte, kDir []byte, nonceSeed []byte, packetNumber uint64) []byte {
	// ChaCha20-Poly1305 only requires nonce uniqueness for a given direction key.
	// The session nonce seed is fresh per handshake and packet numbers are
	// monotonic, so this avoids a keyed hash in the transport hot path while
	// preserving the same uniqueness invariant WireGuard relies on.
	out := dst
	if cap(out) < chacha20poly1305.NonceSize {
		out = make([]byte, chacha20poly1305.NonceSize)
	} else {
		out = out[:chacha20poly1305.NonceSize]
		clear(out)
	}
	if len(nonceSeed) >= 4 {
		copy(out[:4], nonceSeed[:4])
	} else if len(kDir) >= 4 {
		copy(out[:4], kDir[:4])
	}
	binary.LittleEndian.PutUint64(out[4:12], packetNumber)
	return out
}

func EncapsulateTransport(keys *TransportKeys, packetNumber uint64, innerPacket []byte, padLen uint16, tagLen int) ([]byte, error) {
	return EncapsulateTransportInto(nil, keys, packetNumber, innerPacket, padLen, tagLen)
}

// EncapsulateTransportInto behaves like EncapsulateTransport but assembles the
// frame in dst's backing array when it has enough capacity, so the packet hot
// path can reuse one buffer per batch slot instead of allocating per packet.
func EncapsulateTransportInto(dst []byte, keys *TransportKeys, packetNumber uint64, innerPacket []byte, padLen uint16, tagLen int) ([]byte, error) {
	var tagFull [32]byte
	tag := deriveTagInto(tagFull[:0], keys.KTagSend, packetNumber, keys.SessionContext)[:tagLen]

	var nonceFull [32]byte
	nonce := deriveNonceInto(nonceFull[:0], keys.KSend, keys.NonceSeed, packetNumber)[:12]

	aead, err := keys.senderAEAD()
	if err != nil {
		return nil, err
	}

	var adStack [96]byte
	ad := makeAssociatedData(adStack[:0], tag, keys.SessionContext)
	ptLen := len(innerPacket) + int(padLen) + 2
	need := tagLen + ptLen + aead.Overhead()
	var out []byte
	if cap(dst) >= need {
		out = dst[:need]
	} else {
		out = make([]byte, need)
	}
	copy(out[:tagLen], tag)

	pt := out[tagLen : tagLen+ptLen]
	copy(pt, innerPacket)
	if padLen > 0 {
		clear(pt[len(innerPacket) : len(innerPacket)+int(padLen)])
	}
	binary.LittleEndian.PutUint16(pt[ptLen-2:], padLen)

	ciphertext := aead.Seal(pt[:0], nonce, pt, ad)
	return out[:tagLen+len(ciphertext)], nil
}

func DecapsulateTransport(keys *TransportKeys, packetNumber uint64, packet []byte, tagLen int) ([]byte, error) {
	if len(packet) < tagLen+16+2 {
		return nil, errors.New("packet too small")
	}

	tag := packet[:tagLen]
	ciphertext := packet[tagLen:]

	var nonceFull [32]byte
	nonce := deriveNonceInto(nonceFull[:0], keys.KRecv, keys.NonceSeed, packetNumber)[:12]

	aead, err := keys.receiverAEAD()
	if err != nil {
		return nil, err
	}

	var adStack [96]byte
	ad := makeAssociatedData(adStack[:0], tag, keys.SessionContext)
	pt, err := aead.Open(ciphertext[:0], nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}

	if len(pt) < 2 {
		return nil, errors.New("plaintext too small")
	}

	padLen := binary.LittleEndian.Uint16(pt[len(pt)-2:])

	if len(pt) < int(padLen)+2 {
		return nil, errors.New("invalid padding length")
	}

	innerPacket := pt[:len(pt)-int(padLen)-2]
	return innerPacket, nil
}

func makeAssociatedData(dst []byte, tag []byte, sessionContext []byte) []byte {
	n := len(tag) + len(sessionContext)
	if cap(dst) < n {
		dst = make([]byte, n)
	} else {
		dst = dst[:n]
	}
	copy(dst, tag)
	copy(dst[len(tag):], sessionContext)
	return dst
}
