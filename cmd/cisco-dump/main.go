package main

import (
	"os"

	"multi-tun/internal/ciscodumpcli"
)

func main() {
	app := ciscodumpcli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
