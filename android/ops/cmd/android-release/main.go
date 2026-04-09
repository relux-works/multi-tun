package main

import (
	"os"

	"multi-tun/android/ops/androidreleasecli"
)

func main() {
	app := androidreleasecli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
