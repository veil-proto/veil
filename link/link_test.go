package link

import "testing"

const sampleConf = `[Interface]
PrivateKey = 40e859dacd48da2172d6e0e8744c9e33307634759f86442754dd17e404d92e5f
Address = 10.8.0.2/24
NID = aa11
NetSecret = bb22

[Peer]
PublicKey = 990e2b3f56b5625d9f177b46f74ed8d25e94519abcb081877b54009d87e0517e
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`

func TestEncodeDecodeRoundTrip(t *testing.T) {
	l := Encode(sampleConf, "Home Server")
	if l[:len(Scheme)] != Scheme {
		t.Fatalf("link missing scheme: %q", l)
	}
	conf, name, err := Decode(l)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if conf != sampleConf {
		t.Errorf("config text did not round-trip:\n%q", conf)
	}
	if name != "Home Server" {
		t.Errorf("name = %q, want %q", name, "Home Server")
	}
}

func TestEncodeNoName(t *testing.T) {
	conf, name, err := Decode(Encode(sampleConf, ""))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if conf != sampleConf || name != "" {
		t.Errorf("no-name round-trip failed: name=%q", name)
	}
}

func TestDecodeToleratesWhitespace(t *testing.T) {
	l := "  " + Encode(sampleConf, "x") + "\n"
	if _, _, err := Decode(l); err != nil {
		t.Errorf("expected whitespace to be tolerated: %v", err)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := []string{
		"",
		"https://example.com",
		"veil://",              // empty body
		"veil://!!!not-base64", // bad encoding
	}
	for _, c := range cases {
		if _, _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q) = nil error, want error", c)
		}
	}
}
