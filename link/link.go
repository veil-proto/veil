// Package link encodes and decodes veil:// configuration links — a compact,
// shareable representation of a full VEIL client config (the whole .conf text),
// suitable for a QR code, a chat message, or a clipboard paste.
//
// Format:
//
//	veil://<base64url-nopad(config-text)>[#<url-escaped-name>]
//
// The body is the exact config file text, so decoding round-trips losslessly
// back through config.LoadConfig. The optional fragment carries a human-friendly
// name for the tunnel (what the tray shows in its config list).
package link

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// Scheme is the URL scheme for VEIL config links, including the separator.
const Scheme = "veil://"

// Encode builds a veil:// link from config text and an optional display name.
func Encode(configText, name string) string {
	var b strings.Builder
	b.WriteString(Scheme)
	b.WriteString(base64.RawURLEncoding.EncodeToString([]byte(configText)))
	if name != "" {
		b.WriteByte('#')
		b.WriteString(url.PathEscape(name))
	}
	return b.String()
}

// Decode parses a veil:// link, returning the config text and the display name
// (empty if the link carried none). Whitespace around the link is tolerated so
// a value pasted from chat still works.
func Decode(link string) (configText, name string, err error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, Scheme) {
		return "", "", errors.New("not a veil:// link")
	}
	body := link[len(Scheme):]

	if i := strings.IndexByte(body, '#'); i >= 0 {
		name, err = url.PathUnescape(body[i+1:])
		if err != nil {
			return "", "", errors.New("invalid name in link")
		}
		body = body[:i]
	}

	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", "", errors.New("invalid link encoding")
	}
	if len(raw) == 0 {
		return "", "", errors.New("empty link")
	}
	return string(raw), name, nil
}
