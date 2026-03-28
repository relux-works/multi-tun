package main

import (
	"os"

	"multi-tun/internal/vpncorecli"
)

func main() {
	app := vpncorecli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
