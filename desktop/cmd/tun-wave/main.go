package main

import (
	"os"
	"path/filepath"

	"multi-tun/desktop/internal/vless/cli"
)

func main() {
	name := filepath.Base(os.Args[0])
	if name == "" || name == "." {
		name = "tun-wave"
	}
	os.Exit(cli.NewWithName(os.Stdout, os.Stderr, name).Run(os.Args[1:]))
}
