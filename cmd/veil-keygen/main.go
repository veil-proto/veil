// Command veil-keygen is VEIL's key/secret helper, analogous to `wg genkey` /
// `wg pubkey`. All values are lowercase hex.
//
//	veil-keygen                 print "<private> <public>" (a fresh X25519 keypair)
//	veil-keygen private         print a fresh X25519 private key
//	veil-keygen pubkey <priv>   derive the public key for a private key
//	veil-keygen secret          print 32 random bytes (for NID or NetSecret)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func genPrivate() [32]byte {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		die("rng error: %v", err)
	}
	// X25519 clamping (idempotent; keeps the key canonical).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	return priv
}

func pubOf(priv [32]byte) []byte {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		die("x25519: %v", err)
	}
	return pub
}

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "": // keypair
		priv := genPrivate()
		fmt.Printf("%x %x\n", priv[:], pubOf(priv))
	case "private":
		priv := genPrivate()
		fmt.Printf("%x\n", priv[:])
	case "pubkey":
		if len(os.Args) != 3 {
			die("usage: veil-keygen pubkey <private-hex>")
		}
		raw, err := hex.DecodeString(strings.TrimSpace(os.Args[2]))
		if err != nil || len(raw) != 32 {
			die("invalid private key (need 32-byte hex)")
		}
		var priv [32]byte
		copy(priv[:], raw)
		fmt.Printf("%x\n", pubOf(priv))
	case "secret":
		var b [32]byte
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			die("rng error: %v", err)
		}
		fmt.Printf("%x\n", b[:])
	default:
		die("unknown command %q\nusage: veil-keygen [private|pubkey <priv>|secret]", cmd)
	}
}
