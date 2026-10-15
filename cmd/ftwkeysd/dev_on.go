//go:build ftwclouddev

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/srcfl/ftw-cloud/internal/keys"
)

// A development build seals keys with a local file key and signs offers with
// a local key. Whoever reads the file and the state directory has every
// agent key, so a production build has neither.
const devBuild = true

func addFileKeyFlag(fs *flag.FlagSet) *string {
	return fs.String("file-key", "", "a local file key instead of KMS (development only)")
}

// devCommand runs "ftwkeysd filekey -out dev.key".
func devCommand(name string, args []string) bool {
	if name != "filekey" {
		return false
	}
	fs := flag.NewFlagSet("filekey", flag.ExitOnError)
	out := fs.String("out", "", "file to write the key to")
	_ = fs.Parse(args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "filekey: -out is required")
		os.Exit(1)
	}
	if err := keys.MakeFileKey(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return true
}
