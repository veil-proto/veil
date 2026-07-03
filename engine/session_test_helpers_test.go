package engine

import "github.com/veil-proto/veil/transport"

func testTransportKeys(seed byte) *transport.TransportKeys {
	keys := &transport.TransportKeys{
		KSend:          make([]byte, 32),
		KRecv:          make([]byte, 32),
		KTagSend:       make([]byte, 32),
		KTagRecv:       make([]byte, 32),
		SessionContext: make([]byte, 32),
		NonceSeed:      make([]byte, 12),
	}
	for i := range 32 {
		keys.KSend[i] = seed + byte(i)
		keys.KRecv[i] = seed + 0x40 + byte(i)
		keys.KTagSend[i] = seed + 0x80 + byte(i)
		keys.KTagRecv[i] = seed + 0xC0 + byte(i)
		keys.SessionContext[i] = seed ^ byte(i)
	}
	for i := range keys.NonceSeed {
		keys.NonceSeed[i] = seed + 0x20 + byte(i)
	}
	return keys
}
