package main

import (
	"os"

	"multi-tun/desktop/internal/vless/cli"
)

func main() {
	app := cli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
