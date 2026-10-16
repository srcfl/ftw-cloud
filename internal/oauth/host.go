package oauth

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// asciiHost is a host as the owner is shown it and the offer signs it,
// in lower case ASCII. A name with letters outside ASCII goes to its
// punycode form (UTS 46 lookup), so a look-alike spelt with another
// script's letters, such as a Cyrillic с in сlaude.ai, reads as the
// different name it is. An address goes to its canonical form. ok is false
// for a host with no ASCII form, an empty label, a trailing dot, an address
// with a zone, or a name whose last label a browser reads as a number and
// so as an IPv4 address (2130706433, 0177.0.0.1, 0x7f.1).
//
// A name already in ASCII is not checked against the IDNA rules: an
// underscore or a "--" in a label misleads no one, and clients registered
// with one keep working.
func asciiHost(host string) (string, bool) {
	if host == "" || strings.HasSuffix(host, ".") {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		return addr.String(), true
	}
	a := strings.ToLower(host)
	if strings.ContainsFunc(a, func(r rune) bool { return r >= 0x80 }) {
		var err error
		if a, err = idna.Lookup.ToASCII(host); err != nil {
			return "", false
		}
	}
	labels := strings.Split(a, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' || strings.ContainsFunc(l, notHostByte) {
			return "", false
		}
	}
	if len(a) > 253 || isNumber(labels[len(labels)-1]) {
		return "", false
	}
	return a, true
}

// notHostByte is anything but a letter, a digit, a hyphen or an underscore.
func notHostByte(r rune) bool {
	return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
}

// isNumber reports whether a browser's URL parser reads a label as an IPv4
// number: decimal or octal digits, or 0x and hex digits.
func isNumber(l string) bool {
	if rest, ok := strings.CutPrefix(l, "0x"); ok {
		return !strings.ContainsFunc(rest, func(r rune) bool {
			return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f')
		})
	}
	return !strings.ContainsFunc(l, func(r rune) bool { return r < '0' || r > '9' })
}

// asciiHostPort is a URL's host and port with the host in ASCII, for a page
// that names where a link goes. Empty when the host has no ASCII form.
func asciiHostPort(u *url.URL) string {
	h, ok := asciiHost(u.Hostname())
	switch {
	case !ok:
		return ""
	case u.Port() != "":
		return net.JoinHostPort(h, u.Port())
	case strings.Contains(h, ":"):
		return "[" + h + "]"
	}
	return h
}
