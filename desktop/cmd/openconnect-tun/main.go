package main

import (
	"os"

	"multi-tun/desktop/internal/anyconnect/openconnectcli"
)

func main() {
	app := openconnectcli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
