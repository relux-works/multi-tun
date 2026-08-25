package main

import (
	"os"

	"multi-tun/desktop/internal/sshproxy/cli"
)

func main() {
	os.Exit(cli.New(os.Stdout, os.Stderr).Run(os.Args[1:]))
}
