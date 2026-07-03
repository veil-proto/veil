// Package kdf implements the VEIL-KDF-1 reference schedule.
package kdf

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

type PQPolicy uint16

const (
	PQRequired  PQPolicy = 1
	PQPreferred PQPolicy = 2
	ClassicOnly PQPolicy = 3
)

type SecretType uint16

const (
	SecretDHEE           SecretType = 1
	SecretDHES           SecretType = 2
	SecretDHSE           SecretType = 3
	SecretDHSS           SecretType = 4
	SecretPSK            SecretType = 5
	SecretEnrollmentAuth SecretType = 6
	SecretMLKEMC2S       SecretType = 7
	SecretMLKEMS2C       SecretType = 8
)

type InputStatus byte

const (
	InputDisabled InputStatus = 0
	InputPresent  InputStatus = 1
)

type TypedInput struct {
	Type   SecretType
	Status InputStatus
	Value  []byte
}

type SuiteConfig struct {
	KEM                 string
	ClassicalKEX        string
	AEAD                string
	HeaderProtection    string
	TokenMode           string
	PQPolicy            PQPolicy
	PaddingPolicy       string
	FragmentationPolicy string
}

type Chain struct {
	CK [9][32]byte
}

type InitialInputs struct {
	DHEE       TypedInput
	DHES       TypedInput
	DHSE       TypedInput
	DHSS       TypedInput
	PSK        TypedInput
	Enrollment TypedInput
	MLKEMC2S   TypedInput
	MLKEMS2C   TypedInput
}

type HandshakeSecrets struct {
	HandshakeSecret [32]byte
	ConfirmKeyC2S   [32]byte
	ConfirmKeyS2C   [32]byte
	ConfirmMacC2S   [32]byte
	ConfirmMacS2C   [32]byte
	THConf          [32]byte
	MasterSecret    [32]byte
	SessionRoot     [32]byte
	EpochRoot0      [32]byte
}

func DefaultSuite(policy PQPolicy) SuiteConfig {
	return SuiteConfig{
		KEM:                 "ML-KEM-768",
		ClassicalKEX:        "X25519",
		AEAD:                "ChaCha20-Poly1305",
		HeaderProtection:    "HP-CHACHA20-SHA256-SAMPLE",
		TokenMode:           "VEIL-TOKENS-1",
		PQPolicy:            policy,
		PaddingPolicy:       "balanced",
		FragmentationPolicy: "INNER_FRAGMENT-1",
	}
}

func Domain(label string) [32]byte {
	return sha256.Sum256([]byte(label))
}

func (s SuiteConfig) SuiteID() [32]byte {
	h := sha256.New()
	for _, label := range []string{"VEIL-NATIVE/1", "VEIL-RECORD-1", "VEIL-CONTROL-1", "VEIL-KDF-1"} {
		d := Domain(label)
		h.Write(d[:])
	}
	writeSuitePart(hWrite{h}, s.KEM)
	writeSuitePart(hWrite{h}, s.ClassicalKEX)
	writeSuitePart(hWrite{h}, s.AEAD)
	writeSuitePart(hWrite{h}, s.HeaderProtection)
	writeSuitePart(hWrite{h}, "SHA-256")
	writeSuitePart(hWrite{h}, s.TokenMode)
	writeSuitePart(hWrite{h}, fmt.Sprintf("PQ-%d", s.PQPolicy))
	writeSuitePart(hWrite{h}, s.PaddingPolicy)
	writeSuitePart(hWrite{h}, s.FragmentationPolicy)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type hWrite struct {
	h interface{ Write([]byte) (int, error) }
}

func writeSuitePart(w hWrite, s string) {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[0:2], uint16(len(s)))
	w.h.Write(lenBuf[:])
	w.h.Write([]byte(s))
}

func Transcript0(suiteID [32]byte, deploymentID, policyHash []byte) [32]byte {
	h := sha256.New()
	proto := Domain("VEIL-NATIVE/1")
	h.Write(proto[:])
	h.Write(suiteID[:])
	h.Write(deploymentID)
	h.Write(policyHash)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TranscriptNext(prev [32]byte, canonical []byte) [32]byte {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func EncodeTypedInput(in TypedInput) ([]byte, error) {
	if in.Status != InputDisabled && in.Status != InputPresent {
		return nil, fmt.Errorf("kdf: invalid input status %d", in.Status)
	}
	if in.Status == InputDisabled && len(in.Value) != 0 {
		return nil, errors.New("kdf: disabled input must have zero length")
	}
	out := make([]byte, 7+len(in.Value))
	binary.BigEndian.PutUint16(out[0:2], uint16(in.Type))
	out[2] = byte(in.Status)
	binary.BigEndian.PutUint32(out[3:7], uint32(len(in.Value)))
	copy(out[7:], in.Value)
	return out, nil
}

func Disabled(secret SecretType) TypedInput {
	return TypedInput{Type: secret, Status: InputDisabled}
}

func Present(secret SecretType, value []byte) TypedInput {
	return TypedInput{Type: secret, Status: InputPresent, Value: append([]byte(nil), value...)}
}

func MixKey(ck []byte, in TypedInput) ([32]byte, error) {
	wire, err := EncodeTypedInput(in)
	if err != nil {
		return [32]byte{}, err
	}
	prk, err := hkdf.Extract(sha256.New, wire, ck)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], prk)
	return out, nil
}

func Expand(secret []byte, label string, context []byte, n int) ([]byte, error) {
	info := make([]byte, 0, len(label)+len(context))
	info = append(info, label...)
	info = append(info, context...)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

func DeriveInitialChain(ck0 [32]byte, inputs InitialInputs) (Chain, error) {
	c := Chain{}
	c.CK[0] = ck0
	ordered := []TypedInput{
		inputs.DHEE,
		inputs.DHES,
		inputs.DHSE,
		inputs.DHSS,
		inputs.PSK,
		inputs.Enrollment,
		inputs.MLKEMC2S,
		inputs.MLKEMS2C,
	}
	for i, in := range ordered {
		ck, err := MixKey(c.CK[i][:], in)
		if err != nil {
			return Chain{}, err
		}
		c.CK[i+1] = ck
	}
	return c, nil
}

func ConfirmAndRoot(ck8 [32]byte, thf [32]byte) (HandshakeSecrets, error) {
	var hs HandshakeSecrets
	handshakeSecret, err := hkdf.Extract(sha256.New, ck8[:], thf[:])
	if err != nil {
		return hs, err
	}
	copy(hs.HandshakeSecret[:], handshakeSecret)
	c2s, err := Expand(handshakeSecret, "confirm c2s", thf[:], 32)
	if err != nil {
		return hs, err
	}
	s2c, err := Expand(handshakeSecret, "confirm s2c", thf[:], 32)
	if err != nil {
		return hs, err
	}
	copy(hs.ConfirmKeyC2S[:], c2s)
	copy(hs.ConfirmKeyS2C[:], s2c)
	hs.ConfirmMacC2S = mac32(hs.ConfirmKeyC2S[:], thf[:], []byte("client confirm"))
	hs.ConfirmMacS2C = mac32(hs.ConfirmKeyS2C[:], thf[:], []byte("server confirm"))

	h := sha256.New()
	h.Write(thf[:])
	h.Write(hs.ConfirmMacC2S[:])
	h.Write(hs.ConfirmMacS2C[:])
	copy(hs.THConf[:], h.Sum(nil))

	master, err := hkdf.Extract(sha256.New, handshakeSecret, hs.THConf[:])
	if err != nil {
		return hs, err
	}
	copy(hs.MasterSecret[:], master)
	sessionRoot, err := Expand(master, "session root", hs.THConf[:], 32)
	if err != nil {
		return hs, err
	}
	copy(hs.SessionRoot[:], sessionRoot)
	epochRoot0, err := Expand(hs.SessionRoot[:], "epoch root 0", hs.THConf[:], 32)
	if err != nil {
		return hs, err
	}
	copy(hs.EpochRoot0[:], epochRoot0)
	return hs, nil
}

func mac32(key []byte, parts ...[]byte) [32]byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}
