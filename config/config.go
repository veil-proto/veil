package config

import (
	"encoding/hex"
	"fmt"
	"net"
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
	// NetSecretInsecure is set when NetSecret in the config file was the
	// literal sentinel "insecure" rather than a 32-byte hex secret — an
	// explicit, deliberate opt-out of the per-network pre-DH gate, never an
	// implicit default. See Validate().
	NetSecretInsecure bool
	// AllowInsecureNetSecret must also be set (AllowInsecureNetSecretForTestingOnly
	// in the config file) for NetSecretInsecure to pass Validate(). Requiring a
	// second, differently-named key makes "insecure" alone insufficient to run
	// in production by accident — a deployer has to explicitly type out
	// "ForTestingOnly" to enable it. See Validate().
	AllowInsecureNetSecret bool
	Padding                string
	DNS                    string // comma-separated DNS servers set inside the tunnel (client)
	FwMark                 int
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

// Serialize renders the config back into VEIL .conf text (INI-style,
// [Interface] followed by one [Peer] section per peer). It is the inverse of
// LoadConfigString: parsing Serialize's output must reproduce equivalent
// field values (see the round-trip test in config_test.go). Only fields that
// LoadConfigString itself understands are written back out — this is not a
// general-purpose INI writer, just enough for the GUI (and any other caller)
// to persist an in-memory Config it built or edited.
func (c *Config) Serialize() string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	if len(c.Interface.PrivateKey) > 0 {
		fmt.Fprintf(&b, "PrivateKey = %s\n", hex.EncodeToString(c.Interface.PrivateKey))
	}
	if c.Interface.Address != "" {
		fmt.Fprintf(&b, "Address = %s\n", c.Interface.Address)
	}
	if c.Interface.BindAddress != "" {
		fmt.Fprintf(&b, "BindAddress = %s\n", c.Interface.BindAddress)
	}
	if c.Interface.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.Interface.ListenPort)
	}
	if len(c.Interface.NID) > 0 {
		fmt.Fprintf(&b, "NID = %s\n", hex.EncodeToString(c.Interface.NID))
	}
	if c.Interface.NetSecretInsecure {
		b.WriteString("NetSecret = insecure\n")
		if c.Interface.AllowInsecureNetSecret {
			b.WriteString("AllowInsecureNetSecretForTestingOnly = true\n")
		}
	} else if len(c.Interface.NetSecret) > 0 {
		fmt.Fprintf(&b, "NetSecret = %s\n", hex.EncodeToString(c.Interface.NetSecret))
	}
	if c.Interface.Padding != "" {
		fmt.Fprintf(&b, "Padding = %s\n", c.Interface.Padding)
	}
	if c.Interface.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.Interface.DNS)
	}
	if c.Interface.FwMark != 0 {
		fmt.Fprintf(&b, "FwMark = %d\n", c.Interface.FwMark)
	}

	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		if len(p.PublicKey) > 0 {
			fmt.Fprintf(&b, "PublicKey = %s\n", hex.EncodeToString(p.PublicKey))
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive != 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
		if len(p.PresharedKey) > 0 {
			fmt.Fprintf(&b, "PresharedKey = %s\n", hex.EncodeToString(p.PresharedKey))
		}
	}

	return b.String()
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
	if strings.EqualFold(strings.TrimSpace(netSecHex), "insecure") {
		parsedConfig.Interface.NetSecretInsecure = true
	} else if parsedConfig.Interface.NetSecret, err = parseHex(netSecHex); err != nil {
		return nil, fmt.Errorf("invalid NetSecret: %v", err)
	}
	parsedConfig.Interface.AllowInsecureNetSecret, _ = ifaceSec.Key("AllowInsecureNetSecretForTestingOnly").Bool()

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

	if err := parsedConfig.Validate(); err != nil {
		return nil, err
	}
	return &parsedConfig, nil
}

// ValidationError aggregates every problem found by Validate, so a caller can
// report all of them at once instead of stopping at the first.
type ValidationError struct {
	Errors []error
}

func (v *ValidationError) Error() string {
	parts := make([]string, len(v.Errors))
	for i, e := range v.Errors {
		parts[i] = e.Error()
	}
	return "invalid config: " + strings.Join(parts, "; ")
}

// Validate checks structural and cryptographic-length invariants that the
// loader itself does not enforce: exact key lengths, valid endpoints/CIDRs,
// and duplicate peer keys. A config that fails Validate must not be handed
// to engine.New — previously, bad values here were silently truncated,
// zero-padded, or dropped instead of rejected.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if len(c.Interface.PrivateKey) != 32 {
		add("Interface.PrivateKey must be exactly 32 bytes (got %d)", len(c.Interface.PrivateKey))
	}
	if len(c.Interface.NID) != 32 {
		add("Interface.NID must be exactly 32 bytes (got %d)", len(c.Interface.NID))
	}
	if c.Interface.NetSecretInsecure {
		if len(c.Interface.NetSecret) != 0 {
			add("Interface.NetSecret cannot be set when NetSecret = insecure is also used")
		}
		if !c.Interface.AllowInsecureNetSecret {
			add("NetSecret = insecure requires AllowInsecureNetSecretForTestingOnly = true in [Interface] — this is a dev/test-only opt-out of the network membership gate, never a production default")
		}
	} else if len(c.Interface.NetSecret) != 32 {
		add("Interface.NetSecret must be exactly 32 bytes, or explicitly set to \"insecure\" to opt out (got %d bytes)", len(c.Interface.NetSecret))
	}

	seenPeerKeys := make(map[string]int, len(c.Peers))
	for i, p := range c.Peers {
		label := fmt.Sprintf("Peer[%d]", i)
		for _, perr := range p.validate(label) {
			add("%s", perr.Error())
		}
		if len(p.PublicKey) == 32 {
			key := hex.EncodeToString(p.PublicKey)
			if first, dup := seenPeerKeys[key]; dup {
				add("%s.PublicKey is a duplicate of Peer[%d]", label, first)
			} else {
				seenPeerKeys[key] = i
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return &ValidationError{Errors: errs}
}

// Validate checks a single peer in isolation (everything validate() checks
// except cross-peer duplicate-key detection, which only makes sense against
// a full peer set). Used directly by callers adding one peer at a time
// outside a full Config — e.g. Engine.AddPeer.
func (p *PeerConfig) Validate() error {
	errs := p.validate("Peer")
	if len(errs) == 0 {
		return nil
	}
	return &ValidationError{Errors: errs}
}

func (p *PeerConfig) validate(label string) []error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if len(p.PublicKey) != 32 {
		add("%s.PublicKey must be exactly 32 bytes (got %d)", label, len(p.PublicKey))
	}

	if len(p.PresharedKey) != 0 && len(p.PresharedKey) != 32 {
		add("%s.PresharedKey must be exactly 32 bytes if set (got %d)", label, len(p.PresharedKey))
	}

	if p.Endpoint != "" {
		if _, err := net.ResolveUDPAddr("udp", p.Endpoint); err != nil {
			add("%s.Endpoint %q is invalid: %v", label, p.Endpoint, err)
		}
	}

	for _, cidr := range p.AllowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("%s.AllowedIPs entry %q is invalid: %v", label, cidr, err)
		}
	}

	if p.PersistentKeepalive < 0 {
		add("%s.PersistentKeepalive must not be negative (got %d)", label, p.PersistentKeepalive)
	}

	return errs
}
