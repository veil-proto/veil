package kdf

import (
	"bytes"
	"testing"
)

func TestSuiteIDBindsPQPolicy(t *testing.T) {
	required := DefaultSuite(PQRequired).SuiteID()
	classic := DefaultSuite(ClassicOnly).SuiteID()
	if bytes.Equal(required[:], classic[:]) {
		t.Fatal("suite_id did not change when pq_policy changed")
	}
}

func TestTypedDisabledInputDiffersFromPresentZero(t *testing.T) {
	ck0 := Domain("test ck")
	disabled, err := MixKey(ck0[:], Disabled(SecretPSK))
	if err != nil {
		t.Fatal(err)
	}
	presentZero, err := MixKey(ck0[:], Present(SecretPSK, make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(disabled[:], presentZero[:]) {
		t.Fatal("disabled PSK and present all-zero PSK produced same chaining key")
	}
}

func TestInitialChainAndConfirmAreDeterministic(t *testing.T) {
	ck0 := Domain("chain")
	inputs := InitialInputs{
		DHEE:       Present(SecretDHEE, bytes.Repeat([]byte{1}, 32)),
		DHES:       Present(SecretDHES, bytes.Repeat([]byte{2}, 32)),
		DHSE:       Present(SecretDHSE, bytes.Repeat([]byte{3}, 32)),
		DHSS:       Disabled(SecretDHSS),
		PSK:        Disabled(SecretPSK),
		Enrollment: Disabled(SecretEnrollmentAuth),
		MLKEMC2S:   Present(SecretMLKEMC2S, bytes.Repeat([]byte{4}, 32)),
		MLKEMS2C:   Disabled(SecretMLKEMS2C),
	}
	a, err := DeriveInitialChain(ck0, inputs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveInitialChain(ck0, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("chain derivation is not deterministic")
	}
	secrets, err := ConfirmAndRoot(a.CK[8], Domain("THF"))
	if err != nil {
		t.Fatal(err)
	}
	if secrets.EpochRoot0 == ([32]byte{}) {
		t.Fatal("empty epoch root")
	}
}
