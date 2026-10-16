package oauth

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// asciiHost is a host as the owner is shown it and the offer signs it:
// lower case ASCII, a name in its punycode form, so a look-alike spelt with
// another script's letters, such as a Cyrillic с in сlaude.ai, reads as the
// different name it is. An IP address stays as it is. ok is false for a host
// with no ASCII form, which FTW Cloud refuses.
func asciiHost(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host, true
	}
	a, err := idna.Lookup.ToASCII(host)
	if err != nil || a == "" || strings.HasPrefix(a, ".") || strings.Contains(a, "..") {
		return "", false
	}
	return a, true
}

// asciiHostPort is a URL's host and port with the host in ASCII, for a page
// that names where a link goes. Empty when the host has no ASCII form.
func asciiHostPort(u *url.URL) string {
	h, ok := asciiHost(u.Hostname())
	if !ok {
		return ""
	}
	if p := u.Port(); p != "" {
		return net.JoinHostPort(h, p)
	}
	if _, err := netip.ParseAddr(h); err == nil && u.Hostname() != u.Host {
		return "[" + h + "]"
	}
	return h
}
