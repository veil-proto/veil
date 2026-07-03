// Package pq implements the VEIL-PQ-1 ML-KEM-768 control-plane exchange.
package pq

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
)

type Policy byte

const (
	PolicyRequired    Policy = 1
	PolicyPreferred   Policy = 2
	PolicyClassicOnly Policy = 3
)

type Gate struct {
	Policy          Policy
	HybridConfirmed bool
}

type PendingOffer struct {
	decap *mlkem.DecapsulationKey768
}

type Offer struct {
	EncapsulationKey []byte
}

type Answer struct {
	Ciphertext []byte
}

func (g Gate) CanSendUserIP() bool {
	return g.Policy != PolicyRequired || g.HybridConfirmed
}

func NewOffer() (*PendingOffer, Offer, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, Offer{}, err
	}
	return offerFromDecapsulationKey(dk), Offer{EncapsulationKey: dk.EncapsulationKey().Bytes()}, nil
}

func NewDeterministicOffer(seed []byte) (*PendingOffer, Offer, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, Offer{}, err
	}
	return offerFromDecapsulationKey(dk), Offer{EncapsulationKey: dk.EncapsulationKey().Bytes()}, nil
}

func AnswerOffer(offer Offer) (Answer, []byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(offer.EncapsulationKey)
	if err != nil {
		return Answer{}, nil, err
	}
	shared, ct := ek.Encapsulate()
	return Answer{Ciphertext: append([]byte(nil), ct...)}, append([]byte(nil), shared...), nil
}

func ConfirmAnswer(pending *PendingOffer, answer Answer) ([]byte, error) {
	shared, err := pending.decap.Decapsulate(answer.Ciphertext)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), shared...), nil
}

func RefreshSecret(mlkemSharedSecret, refreshTranscriptHash []byte) [32]byte {
	h := sha256.New()
	h.Write(mlkemSharedSecret)
	h.Write(refreshTranscriptHash)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func FoldRefresh(epochRootCurrent [32]byte, pqRefreshSecret [32]byte, refreshTranscriptHash []byte) ([32]byte, error) {
	ikm := make([]byte, 0, len("pq refresh")+len(pqRefreshSecret)+len(refreshTranscriptHash))
	ikm = append(ikm, "pq refresh"...)
	ikm = append(ikm, pqRefreshSecret[:]...)
	ikm = append(ikm, refreshTranscriptHash...)
	next, err := hkdf.Extract(sha256.New, ikm, epochRootCurrent[:])
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], next)
	return out, nil
}

func offerFromDecapsulationKey(dk *mlkem.DecapsulationKey768) *PendingOffer {
	return &PendingOffer{decap: dk}
}
