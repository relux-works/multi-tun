package main

import (
	"os"

	"multi-tun/desktop/internal/anyconnect/ciscodumpcli"
)

func main() {
	app := ciscodumpcli.New(os.Stdout, os.Stderr, os.Args[0])
	os.Exit(app.Run(os.Args[1:]))
}
