package keys

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeer refuses a unix connection from any user but uid, or from any
// user but this process's own when uid is negative.
func checkPeer(c *net.UnixConn, uid int) error {
	if uid < 0 {
		uid = os.Getuid()
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if int(cred.Uid) != uid {
		return errors.New("keys: a peer of another user")
	}
	return nil
}
