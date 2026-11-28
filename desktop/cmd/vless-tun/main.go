package main

import (
	"os"
	"path/filepath"

	"multi-tun/desktop/internal/vless/cli"
)

func main() {
	name := filepath.Base(os.Args[0])
	if name == "" || name == "." {
		name = "vless-tun"
	}
	app := cli.NewWithName(os.Stdout, os.Stderr, name)
	os.Exit(app.Run(os.Args[1:]))
}
