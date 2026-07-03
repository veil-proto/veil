// Package epoch implements VEIL v1 epoch key derivation and ratcheting.
package epoch

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	veilkdf "github.com/veil-proto/veil/kdf"
)

const keyBlockLen = 360

type Keys struct {
	TXAEADKey       [32]byte
	RXAEADKey       [32]byte
	TXNoncePrefix   [4]byte
	RXNoncePrefix   [4]byte
	TXRouteTokenKey [32]byte
	RXRouteTokenKey [32]byte
	TXHPKey         [32]byte
	RXHPKey         [32]byte
	TXPaddingKey    [32]byte
	RXPaddingKey    [32]byte
	TXControlKey    [32]byte
	RXControlKey    [32]byte
	ReplaySalt      [32]byte
}

func Context(sessionIDHidden []byte, epochNumber, pathID uint64, tokenPolicy []byte, thConf [32]byte) [32]byte {
	h := sha256.New()
	h.Write(sessionIDHidden)
	var b [8]byte
	binary.BigEndian.PutUint64(b[0:8], epochNumber)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[0:8], pathID)
	h.Write(b[:])
	h.Write(tokenPolicy)
	h.Write(thConf[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func DeriveKeys(epochRoot [32]byte, epochContext [32]byte) (Keys, error) {
	block, err := veilkdf.Expand(epochRoot[:], "epoch keys", epochContext[:], keyBlockLen)
	if err != nil {
		return Keys{}, err
	}
	var k Keys
	off := 0
	take32 := func(dst *[32]byte) {
		copy(dst[:], block[off:off+32])
		off += 32
	}
	take32(&k.TXAEADKey)
	take32(&k.RXAEADKey)
	copy(k.TXNoncePrefix[:], block[off:off+4])
	off += 4
	copy(k.RXNoncePrefix[:], block[off:off+4])
	off += 4
	take32(&k.TXRouteTokenKey)
	take32(&k.RXRouteTokenKey)
	take32(&k.TXHPKey)
	take32(&k.RXHPKey)
	take32(&k.TXPaddingKey)
	take32(&k.RXPaddingKey)
	take32(&k.TXControlKey)
	take32(&k.RXControlKey)
	take32(&k.ReplaySalt)
	return k, nil
}

func Advance(epochRoot [32]byte, epochContext [32]byte, optionalPQRefreshSecret []byte) ([32]byte, error) {
	ikm := make([]byte, 0, len("advance")+len(epochContext)+len(optionalPQRefreshSecret))
	ikm = append(ikm, "advance"...)
	ikm = append(ikm, epochContext[:]...)
	ikm = append(ikm, optionalPQRefreshSecret...)
	next, err := hkdf.Extract(sha256.New, ikm, epochRoot[:])
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], next)
	return out, nil
}
