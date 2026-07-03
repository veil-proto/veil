package config

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"
)

type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

type InterfaceConfig struct {
	PrivateKey  []byte
	Address     string
	BindAddress string
	ListenPort  int
	NID         []byte
	NetSecret   []byte
	Padding     string
	DNS         string // comma-separated DNS servers set inside the tunnel (client)
	FwMark      int
}

type PeerConfig struct {
	PublicKey           []byte
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int
	PresharedKey        []byte
}

func parseHex(s string) ([]byte, error) {
	// Simple wrapper for hex decode.
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// LoadConfig reads and parses a VEIL config file from disk.
func LoadConfig(path string) (*Config, error) {
	return loadFrom(path)
}

// LoadConfigString parses a VEIL config from in-memory text (e.g. received over
// the control channel or decoded from a veil:// link) rather than a file.
func LoadConfigString(text string) (*Config, error) {
	return loadFrom([]byte(text))
}

func loadFrom(source any) (*Config, error) {
	// AllowNonUniqueSections keeps each [Peer] block distinct; the default merges
	// same-named sections, which would collapse a multi-client server config into
	// a single peer.
	cfg, err := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true}, source)
	if err != nil {
		return nil, err
	}

	var parsedConfig Config

	// Parse Interface
	ifaceSec, err := cfg.GetSection("Interface")
	if err != nil {
		return nil, fmt.Errorf("missing [Interface] section")
	}

	privKeyHex := ifaceSec.Key("PrivateKey").String()
	if parsedConfig.Interface.PrivateKey, err = parseHex(privKeyHex); err != nil {
		return nil, fmt.Errorf("invalid PrivateKey: %v", err)
	}

	parsedConfig.Interface.Address = ifaceSec.Key("Address").String()
	parsedConfig.Interface.BindAddress = ifaceSec.Key("BindAddress").String()

	portStr := ifaceSec.Key("ListenPort").String()
	if portStr != "" {
		if parsedConfig.Interface.ListenPort, err = strconv.Atoi(portStr); err != nil {
			return nil, fmt.Errorf("invalid ListenPort: %v", err)
		}
	}

	nidHex := ifaceSec.Key("NID").String()
	if parsedConfig.Interface.NID, err = parseHex(nidHex); err != nil {
		return nil, fmt.Errorf("invalid NID: %v", err)
	}

	netSecHex := ifaceSec.Key("NetSecret").String()
	if parsedConfig.Interface.NetSecret, err = parseHex(netSecHex); err != nil {
		return nil, fmt.Errorf("invalid NetSecret: %v", err)
	}

	parsedConfig.Interface.Padding = ifaceSec.Key("Padding").String()
	parsedConfig.Interface.DNS = ifaceSec.Key("DNS").String()

	fwmarkStr := ifaceSec.Key("FwMark").String()
	if fwmarkStr != "" {
		if strings.HasPrefix(fwmarkStr, "0x") {
			fwmark, err := strconv.ParseInt(fwmarkStr[2:], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid FwMark: %v", err)
			}
			parsedConfig.Interface.FwMark = int(fwmark)
		} else {
			fwmark, err := strconv.Atoi(fwmarkStr)
			if err != nil {
				return nil, fmt.Errorf("invalid FwMark: %v", err)
			}
			parsedConfig.Interface.FwMark = fwmark
		}
	}
	// Parse Peers (each [Peer] block kept distinct via AllowNonUniqueSections).
	peerSections, _ := cfg.SectionsByName("Peer")
	for _, sec := range peerSections {
		var peer PeerConfig

		pubKeyHex := sec.Key("PublicKey").String()
		if peer.PublicKey, err = parseHex(pubKeyHex); err != nil {
			return nil, fmt.Errorf("invalid PublicKey: %v", err)
		}

		allowedIPsStr := sec.Key("AllowedIPs").String()
		if allowedIPsStr != "" {
			parts := strings.Split(allowedIPsStr, ",")
			for _, part := range parts {
				peer.AllowedIPs = append(peer.AllowedIPs, strings.TrimSpace(part))
			}
		}

		peer.Endpoint = sec.Key("Endpoint").String()

		keepaliveStr := sec.Key("PersistentKeepalive").String()
		if keepaliveStr != "" {
			if peer.PersistentKeepalive, err = strconv.Atoi(keepaliveStr); err != nil {
				return nil, fmt.Errorf("invalid PersistentKeepalive: %v", err)
			}
		}

		pskHex := sec.Key("PresharedKey").String()
		if peer.PresharedKey, err = parseHex(pskHex); err != nil {
			return nil, fmt.Errorf("invalid PresharedKey: %v", err)
		}

		parsedConfig.Peers = append(parsedConfig.Peers, peer)
	}

	return &parsedConfig, nil
}
