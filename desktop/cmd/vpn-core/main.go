package main

import (
	"os"

	"multi-tun/desktop/internal/core/vpncorecli"
)

func main() {
	app := vpncorecli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
