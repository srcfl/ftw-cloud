//go:build !ftwclouddev

package main

import "flag"

// A production build has no file key and no local offer key: both keys live
// in KMS.
const devBuild = false

func addFileKeyFlag(*flag.FlagSet) *string { return new(string) }

func devCommand(string, []string) bool { return false }
