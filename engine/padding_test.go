package engine

import (
	"testing"

	"github.com/veil-proto/veil/transport"
)

// TestTransportPadLenLightQuantizes verifies the "light" default actually pads
// (the Phase E hole) and quantizes the observable frame length to the 128-byte
// grid instead of leaking the exact inner size.
func TestTransportPadLenLightQuantizes(t *testing.T) {
	for innerLen := 0; innerLen <= maxTransportPlaintext; innerLen++ {
		pad := int(transportPadLen(innerLen, "light"))
		total := innerLen + 2 + pad // plaintext = inner + pad_len(2) + pad

		// Never exceed the outer budget.
		if innerLen+pad+transportOverhead > maxOuterPayload {
			t.Fatalf("innerLen=%d pad=%d exceeds maxOuterPayload", innerLen, pad)
		}
		// When there is room to reach the next grid line, the padded plaintext
		// must sit exactly on it; near the ceiling padding is clamped and this
		// relaxes, which is expected.
		if innerLen+padQuantum+transportOverhead <= maxOuterPayload {
			if total%padQuantum != 0 {
				t.Fatalf("innerLen=%d: padded plaintext %d not on %d grid", innerLen, total, padQuantum)
			}
		}
	}
}

// TestTransportPadLenNoneIsBare confirms "none" is the only mode that leaks the
// exact size (no padding at all).
func TestTransportPadLenNoneIsBare(t *testing.T) {
	for _, innerLen := range []int{0, 1, 100, 500, 1200} {
		if pad := transportPadLen(innerLen, "none"); pad != 0 {
			t.Errorf("none innerLen=%d: got pad %d, want 0", innerLen, pad)
		}
	}
}

// TestTransportPadRoundTrips ensures padded frames still decrypt back to the
// original inner packet across every mode (padding is stripped on receive).
func TestTransportPadRoundTrips(t *testing.T) {
	keys := &transport.TransportKeys{
		KSend:          make([]byte, 32),
		KRecv:          make([]byte, 32),
		KTagSend:       make([]byte, 32),
		KTagRecv:       make([]byte, 32),
		SessionContext: make([]byte, 32),
		NonceSeed:      make([]byte, 32),
	}
	for i := range keys.KSend {
		keys.KSend[i] = byte(i)
		keys.KRecv[i] = byte(i)
		keys.KTagSend[i] = byte(i + 1)
		keys.KTagRecv[i] = byte(i + 1)
	}

	inner := make([]byte, 137)
	for i := range inner {
		inner[i] = byte(i)
	}

	for _, mode := range []string{"none", "light", "medium", "heavy"} {
		pad := transportPadLen(len(inner), mode)
		enc, err := transport.EncapsulateTransport(keys, 0, inner, pad, 16)
		if err != nil {
			t.Fatalf("mode %s: encapsulate: %v", mode, err)
		}
		out, err := transport.DecapsulateTransport(keys, 0, enc, 16)
		if err != nil {
			t.Fatalf("mode %s: decapsulate: %v", mode, err)
		}
		if string(out) != string(inner) {
			t.Fatalf("mode %s: round-trip mismatch (len %d vs %d)", mode, len(out), len(inner))
		}
	}
}
