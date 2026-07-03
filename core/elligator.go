package core

// Elligator2 encoding of X25519 ephemeral public keys.
//
// This is the load-bearing piece of VEIL v0.3's "indistinguishability by
// construction" design. A raw X25519 public key is the u-coordinate of a point
// on Curve25519: only about half of all 32-byte strings are valid u-coordinates,
// so a stream that begins with a curve point is statistically distinguishable
// from uniform random noise. That is one structural property no amount of
// basic fixed padding can remove.
//
// Elligator2 maps a curve point to a 32-byte "representative" that is
// computationally indistinguishable from a uniform random string. We put the
// representative on the wire; both sides recover the real public key from it and
// run the ordinary X25519 / hashing on the real point.
//
// Forward map (representative -> point) is provided by the vetted
// gitlab.com/yawning/edwards25519-extra implementation. The inverse map
// (point -> representative) is implemented here following Loup Vaillant's
// reference (Monocypher crypto_elligator_rev). Correctness is gated by a
// round-trip test against the library's forward map (see elligator_test.go).

import (
	"crypto/rand"
	"io"

	"filippo.io/edwards25519/field"
	"gitlab.com/yawning/edwards25519-extra/elligator2"
	"golang.org/x/crypto/curve25519"
)

// feA returns the Montgomery curve constant A = 486662 as a field element.
func feA() *field.Element {
	var b [32]byte
	// 486662 = 0x076D06, little-endian.
	b[0] = 0x06
	b[1] = 0x6D
	b[2] = 0x07
	e, _ := new(field.Element).SetBytes(b[:])
	return e
}

// elligatorRev computes the Elligator2 representative of an X25519 public key.
// tweak supplies fresh randomness: bit 0 selects the map branch, bits 6-7 fill
// the two unused high bits of the representative so the full 32 bytes look
// uniform. It returns ok=false when the point has no representative (~half of
// all points), in which case the caller retries with a fresh ephemeral.
func elligatorRev(pubkey [32]byte, tweak byte) (rep [32]byte, ok bool) {
	u, err := new(field.Element).SetBytes(pubkey[:])
	if err != nil {
		return rep, false
	}

	A := feA()
	uA := new(field.Element).Add(u, A) // u + A

	// denom = -2 * u * (u + A)
	denom := new(field.Element).Multiply(u, uA)
	denom.Add(denom, denom) // 2 * u * (u+A)
	denom.Negate(denom)     // -2 * u * (u+A)

	one := new(field.Element).One()
	// root = 1 / sqrt(denom); wasSquare == 0 means the point is not representable.
	root, wasSquare := new(field.Element).SqrtRatio(one, denom)
	if wasSquare == 0 {
		return rep, false
	}

	// Select the numerator: u+A if the low tweak bit is set, else u.
	t1 := new(field.Element).Select(uA, u, int(tweak&1))
	r := new(field.Element).Multiply(t1, root)

	// Canonicalize to the non-negative representative in [0, (p-1)/2]:
	// negate r when 2*r wraps mod p (i.e. r is in the upper half).
	two := new(field.Element).Add(r, r)
	negR := new(field.Element).Negate(r)
	r.Select(negR, r, two.IsNegative())

	copy(rep[:], r.Bytes())
	// r <= (p-1)/2 < 2^254, so bits 254 and 255 are clear; fill them with noise.
	rep[31] |= tweak & 0xC0
	return rep, true
}

// elligatorMap recovers the X25519 public key (u-coordinate) from a 32-byte
// representative received on the wire.
func elligatorMap(rep [32]byte) [32]byte {
	var b [32]byte
	copy(b[:], rep[:])
	b[31] &= 0x3F // strip the two random high bits before decoding

	r, _ := new(field.Element).SetBytes(b[:])
	u, _ := elligator2.MontgomeryFlavor(r)

	var out [32]byte
	copy(out[:], u.Bytes())
	return out
}

// GenerateElligatorKeypair returns a clamped X25519 private scalar together with
// the Elligator2 representative of its public key. It retries until the public
// key happens to be representable (~2 iterations on average).
func GenerateElligatorKeypair() (priv [32]byte, rep [32]byte, err error) {
	for {
		if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
			return
		}
		// X25519 clamping; keeps DH and the representable point set consistent.
		priv[0] &= 248
		priv[31] &= 127
		priv[31] |= 64

		pubSlice, e := curve25519.X25519(priv[:], curve25519.Basepoint)
		if e != nil {
			err = e
			return
		}
		var pub [32]byte
		copy(pub[:], pubSlice)

		var tweak [1]byte
		if _, err = io.ReadFull(rand.Reader, tweak[:]); err != nil {
			return
		}
		if r, ok := elligatorRev(pub, tweak[0]); ok {
			return priv, r, nil
		}
	}
}

// PublicFromRep is the exported decoder used by the handshake receive path.
func PublicFromRep(rep [32]byte) [32]byte { return elligatorMap(rep) }
