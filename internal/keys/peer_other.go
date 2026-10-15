//go:build !linux && !darwin

package keys

import (
	"errors"
	"net"
)

// checkPeer cannot tell who is on the other end here, so it refuses.
func checkPeer(*net.UnixConn, int) error {
	return errors.New("keys: peer credentials are not available on this system")
}
