package recordv1

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RouteTokenSize = 16
	SeqSize        = 8
	HeaderSize     = RouteTokenSize + SeqSize
)

var (
	ErrPacketTooSmall = errors.New("recordv1: packet too small")
	ErrReplay         = errors.New("recordv1: replayed packet")
)

type DirectionKeys struct {
	AEADKey       [32]byte
	NoncePrefix   [4]byte
	HPKey         [32]byte
	RecordContext []byte
}

func Seal(keys DirectionKeys, routeToken [16]byte, seq uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(keys.AEADKey[:])
	if err != nil {
		return nil, err
	}
	seqPlain := encodeSeq(seq)
	nonce := makeNonce(keys.NoncePrefix, seqPlain)
	ad := associatedData(routeToken, seqPlain, keys.RecordContext)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, ad)
	mask, err := hpMask(keys.HPKey, ciphertext[:16], routeToken, keys.RecordContext)
	if err != nil {
		return nil, err
	}
	seqProtected := xor8(seqPlain, mask)
	out := make([]byte, 0, HeaderSize+len(ciphertext))
	out = append(out, routeToken[:]...)
	out = append(out, seqProtected[:]...)
	out = append(out, ciphertext...)
	return out, nil
}

func Open(keys DirectionKeys, replay *ReplayWindow, packet []byte) ([16]byte, uint64, []byte, error) {
	if len(packet) < HeaderSize+chacha20poly1305.Overhead {
		return [16]byte{}, 0, nil, ErrPacketTooSmall
	}
	var routeToken [16]byte
	copy(routeToken[:], packet[:16])
	ciphertext := packet[HeaderSize:]
	mask, err := hpMask(keys.HPKey, ciphertext[:16], routeToken, keys.RecordContext)
	if err != nil {
		return [16]byte{}, 0, nil, err
	}
	var seqProtected [8]byte
	copy(seqProtected[:], packet[16:24])
	seqPlain := xor8(seqProtected, mask)
	seq := binary.BigEndian.Uint64(seqPlain[:])
	if replay != nil && !replay.PreCheck(seq) {
		return routeToken, seq, nil, ErrReplay
	}
	aead, err := chacha20poly1305.New(keys.AEADKey[:])
	if err != nil {
		return routeToken, seq, nil, err
	}
	nonce := makeNonce(keys.NoncePrefix, seqPlain)
	ad := associatedData(routeToken, seqPlain, keys.RecordContext)
	pt, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return routeToken, seq, nil, err
	}
	if replay != nil && !replay.Commit(seq) {
		return routeToken, seq, nil, ErrReplay
	}
	return routeToken, seq, pt, nil
}

func NewAEAD(keys DirectionKeys) (cipher.AEAD, error) {
	return chacha20poly1305.New(keys.AEADKey[:])
}

func encodeSeq(seq uint64) [8]byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[0:8], seq)
	return out
}

func makeNonce(prefix [4]byte, seq [8]byte) [12]byte {
	var nonce [12]byte
	copy(nonce[:4], prefix[:])
	copy(nonce[4:], seq[:])
	return nonce
}

func associatedData(routeToken [16]byte, seqPlain [8]byte, context []byte) []byte {
	out := make([]byte, 0, 24+len(context))
	out = append(out, routeToken[:]...)
	out = append(out, seqPlain[:]...)
	out = append(out, context...)
	return out
}

func hpMask(key [32]byte, sample []byte, routeToken [16]byte, context []byte) ([8]byte, error) {
	h := sha256.New()
	h.Write(sample)
	h.Write(routeToken[:])
	h.Write(context)
	digest := h.Sum(nil)
	nonce := digest[4:16]
	counter := binary.LittleEndian.Uint32(digest[0:4])
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		return [8]byte{}, err
	}
	c.SetCounter(counter)
	block := make([]byte, 64)
	c.XORKeyStream(block, block)
	var out [8]byte
	copy(out[:], block[:8])
	return out, nil
}

func xor8(a [8]byte, b [8]byte) [8]byte {
	var out [8]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}
