package core

import (
	"golang.org/x/crypto/blake2s"
)

const (
	Version       = "veil-v0.2-lite"
	CryptoSuite   = "X25519-BLAKE2s-ChaCha20Poly1305"
)

// DeriveNID derives the Network Identifier.
func DeriveNID(networkName string, paddingProfile string) []byte {
	// NID = BLAKE2s("veil-v0.2-lite" || network_name || crypto_suite || profile)
	h, _ := blake2s.New256(nil)
	h.Write([]byte(Version))
	h.Write([]byte(networkName))
	h.Write([]byte(CryptoSuite))
	h.Write([]byte(paddingProfile))
	return h.Sum(nil)
}

// DeriveMac1Key derives the key used for MAC1.
// K_mac1 = BLAKE2s(key = K_net, data = NID || label || S_pub)
func DeriveMac1Key(kNet []byte, nid []byte, label string, sPub []byte) ([]byte, error) {
	var key []byte
	if len(kNet) > 32 {
		h, _ := blake2s.New256(nil)
		h.Write(kNet)
		key = h.Sum(nil)
	} else {
		key = kNet
	}

	h, err := blake2s.New256(key)
	if err != nil {
		return nil, err
	}
	h.Write(nid)
	h.Write([]byte(label))
	h.Write(sPub)
	return h.Sum(nil), nil
}

// CalculateMac1 computes the MAC1 tag.
// mac1 = BLAKE2s-MAC(key = K_mac1, data = randomized_prefix || E_i_pub || ciphertext_1)
func CalculateMac1(kMac1 []byte, data []byte) ([]byte, error) {
	var key []byte
	if len(kMac1) > 32 {
		h, _ := blake2s.New256(nil)
		h.Write(kMac1)
		key = h.Sum(nil)
	} else {
		key = kMac1
	}

	h, err := blake2s.New256(key)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}
