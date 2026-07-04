package config

import (
	"strings"
	"testing"
)

func validKeyHex() string {
	return strings.Repeat("ab", 32)
}

func baseValidConfigText() string {
	return "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = " + validKeyHex() + "\n" +
		"Address = 10.0.0.1/24\n" +
		"[Peer]\n" +
		"PublicKey = " + validKeyHex() + "\n" +
		"AllowedIPs = 10.0.0.0/24, 192.168.1.0/24\n" +
		"Endpoint = example.com:51820\n"
}

func TestLoadConfigString_ValidConfigPasses(t *testing.T) {
	cfg, err := LoadConfigString(baseValidConfigText())
	if err != nil {
		t.Fatalf("expected valid config to load, got: %v", err)
	}
	if len(cfg.Interface.PrivateKey) != 32 {
		t.Fatalf("PrivateKey not parsed to 32 bytes")
	}
}

func TestLoadConfigString_ShortPrivateKeyRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = aabb\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = " + validKeyHex() + "\n"
	if _, err := LoadConfigString(text); err == nil {
		t.Fatal("expected a short PrivateKey to be rejected, got nil error")
	}
}

func TestLoadConfigString_NetSecretInsecureSentinel(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = insecure\n" +
		"AllowInsecureNetSecretForTestingOnly = true\n"
	cfg, err := LoadConfigString(text)
	if err != nil {
		t.Fatalf("expected NetSecret = insecure to be accepted, got: %v", err)
	}
	if !cfg.Interface.NetSecretInsecure {
		t.Fatal("expected NetSecretInsecure to be true")
	}
	if !cfg.Interface.AllowInsecureNetSecret {
		t.Fatal("expected AllowInsecureNetSecret to be true")
	}
	if len(cfg.Interface.NetSecret) != 0 {
		t.Fatal("expected NetSecret to be empty when insecure sentinel is used")
	}
}

// TestLoadConfigString_NetSecretInsecureWithoutFlagRejected is a regression
// test for P1.5 (VEIL-Combined-Roadmap.md): "NetSecret = insecure" alone used
// to be a silently-accepted production footgun with no warning. It must now
// require the differently-named AllowInsecureNetSecretForTestingOnly key too.
func TestLoadConfigString_NetSecretInsecureWithoutFlagRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = insecure\n"
	if _, err := LoadConfigString(text); err == nil {
		t.Fatal("expected NetSecret = insecure without AllowInsecureNetSecretForTestingOnly to be rejected")
	}
}

func TestLoadConfigString_MissingNetSecretRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n"
	if _, err := LoadConfigString(text); err == nil {
		t.Fatal("expected missing NetSecret (without insecure sentinel) to be rejected")
	}
}

func TestLoadConfigString_DuplicatePeerKeysRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = " + validKeyHex() + "\n" +
		"[Peer]\n" +
		"PublicKey = " + validKeyHex() + "\n" +
		"[Peer]\n" +
		"PublicKey = " + validKeyHex() + "\n"
	_, err := LoadConfigString(text)
	if err == nil {
		t.Fatal("expected duplicate peer public keys to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected error to mention duplicate peer key, got: %v", err)
	}
}

func TestLoadConfigString_BadCIDRRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = " + validKeyHex() + "\n" +
		"[Peer]\n" +
		"PublicKey = " + validKeyHex() + "\n" +
		"AllowedIPs = not-a-cidr\n"
	if _, err := LoadConfigString(text); err == nil {
		t.Fatal("expected an invalid AllowedIPs CIDR to be rejected")
	}
}

func TestLoadConfigString_BadEndpointRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = " + validKeyHex() + "\n" +
		"[Peer]\n" +
		"PublicKey = " + validKeyHex() + "\n" +
		"Endpoint = example.com:notaport\n"
	if _, err := LoadConfigString(text); err == nil {
		t.Fatal("expected an invalid Endpoint to be rejected")
	}
}

func TestLoadConfigString_BadPresharedKeyLengthRejected(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = " + validKeyHex() + "\n" +
		"[Peer]\n" +
		"PublicKey = " + validKeyHex() + "\n" +
		"PresharedKey = aabb\n"
	if _, err := LoadConfigString(text); err == nil {
		t.Fatal("expected a short PresharedKey to be rejected")
	}
}

func TestSerialize_RoundTrip(t *testing.T) {
	cfg, err := LoadConfigString(baseValidConfigText())
	if err != nil {
		t.Fatalf("load original: %v", err)
	}

	serialized := cfg.Serialize()

	cfg2, err := LoadConfigString(serialized)
	if err != nil {
		t.Fatalf("load serialized output: %v\n--- serialized ---\n%s", err, serialized)
	}

	if !bytesEqual(cfg.Interface.PrivateKey, cfg2.Interface.PrivateKey) {
		t.Errorf("PrivateKey mismatch: %x vs %x", cfg.Interface.PrivateKey, cfg2.Interface.PrivateKey)
	}
	if cfg.Interface.Address != cfg2.Interface.Address {
		t.Errorf("Address mismatch: %q vs %q", cfg.Interface.Address, cfg2.Interface.Address)
	}
	if !bytesEqual(cfg.Interface.NID, cfg2.Interface.NID) {
		t.Errorf("NID mismatch: %x vs %x", cfg.Interface.NID, cfg2.Interface.NID)
	}
	if !bytesEqual(cfg.Interface.NetSecret, cfg2.Interface.NetSecret) {
		t.Errorf("NetSecret mismatch: %x vs %x", cfg.Interface.NetSecret, cfg2.Interface.NetSecret)
	}
	if cfg.Interface.NetSecretInsecure != cfg2.Interface.NetSecretInsecure {
		t.Errorf("NetSecretInsecure mismatch: %v vs %v", cfg.Interface.NetSecretInsecure, cfg2.Interface.NetSecretInsecure)
	}
	if len(cfg2.Peers) != len(cfg.Peers) {
		t.Fatalf("peer count mismatch: %d vs %d", len(cfg2.Peers), len(cfg.Peers))
	}
	for i := range cfg.Peers {
		p1, p2 := cfg.Peers[i], cfg2.Peers[i]
		if !bytesEqual(p1.PublicKey, p2.PublicKey) {
			t.Errorf("Peer[%d].PublicKey mismatch: %x vs %x", i, p1.PublicKey, p2.PublicKey)
		}
		if strings.Join(p1.AllowedIPs, ",") != strings.Join(p2.AllowedIPs, ",") {
			t.Errorf("Peer[%d].AllowedIPs mismatch: %v vs %v", i, p1.AllowedIPs, p2.AllowedIPs)
		}
		if p1.Endpoint != p2.Endpoint {
			t.Errorf("Peer[%d].Endpoint mismatch: %q vs %q", i, p1.Endpoint, p2.Endpoint)
		}
		if p1.PersistentKeepalive != p2.PersistentKeepalive {
			t.Errorf("Peer[%d].PersistentKeepalive mismatch: %d vs %d", i, p1.PersistentKeepalive, p2.PersistentKeepalive)
		}
	}
}

func TestSerialize_InsecureSentinelRoundTrip(t *testing.T) {
	text := "[Interface]\n" +
		"PrivateKey = " + validKeyHex() + "\n" +
		"NID = " + validKeyHex() + "\n" +
		"NetSecret = insecure\n" +
		"AllowInsecureNetSecretForTestingOnly = true\n"
	cfg, err := LoadConfigString(text)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg2, err := LoadConfigString(cfg.Serialize())
	if err != nil {
		t.Fatalf("load serialized: %v", err)
	}
	if !cfg2.Interface.NetSecretInsecure {
		t.Fatal("expected NetSecretInsecure to round-trip as true")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestValidate_AggregatesMultipleErrors(t *testing.T) {
	cfg := &Config{
		Interface: InterfaceConfig{}, // everything missing
		Peers: []PeerConfig{
			{PublicKey: []byte{0x01}}, // wrong length
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	// PrivateKey, NID, NetSecret, and Peer[0].PublicKey should all fail.
	if len(ve.Errors) < 4 {
		t.Fatalf("expected at least 4 aggregated errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}
