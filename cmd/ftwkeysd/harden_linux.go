package main

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// harden makes the process not dumpable: no core file, and no ptrace attach
// from another process of the same user. Agent keys and session keys live in
// this process's memory while a session is open.
func harden() {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		slog.Warn("could not turn off core dumps", "err", err)
	}
}
