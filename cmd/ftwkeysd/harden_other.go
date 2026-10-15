//go:build !linux

package main

// harden has nothing to set outside Linux, where the service runs.
func harden() {}
