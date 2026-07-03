package pq

import (
	"bytes"
	"testing"
)

func TestMLKEM768Exchange(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	pending, offer, err := NewDeterministicOffer(seed)
	if err != nil {
		t.Fatal(err)
	}
	answer, responderSecret, err := AnswerOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	initiatorSecret, err := ConfirmAnswer(pending, answer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initiatorSecret, responderSecret) {
		t.Fatal("ML-KEM secrets differ")
	}
}

func TestPQRequiredGate(t *testing.T) {
	if (Gate{Policy: PolicyRequired}).CanSendUserIP() {
		t.Fatal("PQ_REQUIRED allowed user IP before confirmation")
	}
	if !(Gate{Policy: PolicyRequired, HybridConfirmed: true}).CanSendUserIP() {
		t.Fatal("confirmed PQ_REQUIRED gate blocked user IP")
	}
	if !(Gate{Policy: PolicyClassicOnly}).CanSendUserIP() {
		t.Fatal("CLASSIC_ONLY should not require hybrid confirmation")
	}
}

func TestRefreshFoldChangesEpochRoot(t *testing.T) {
	var root [32]byte
	root[0] = 1
	secret := RefreshSecret([]byte("mlkem"), []byte("transcript"))
	next, err := FoldRefresh(root, secret, []byte("transcript"))
	if err != nil {
		t.Fatal(err)
	}
	if next == root {
		t.Fatal("refresh did not change epoch root")
	}
}
