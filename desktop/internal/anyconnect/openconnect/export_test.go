package openconnect

import (
	"context"
	"os"
	"time"
)

type CiscoTestSeams struct {
	CommandTimeout      time.Duration
	VPNBinaryCandidates []string
	PathStat            func(string) (os.FileInfo, error)
	RunCommand          func(context.Context, string, ...string) ([]byte, error)
}

func InstallCiscoTestSeams(seams CiscoTestSeams) func() {
	originalTimeout := cmdTimeout
	originalCandidates := vpnBinaryCandidates
	originalPathStat := pathStat
	originalRunCommand := runCommand

	cmdTimeout = seams.CommandTimeout
	vpnBinaryCandidates = seams.VPNBinaryCandidates
	pathStat = seams.PathStat
	runCommand = seams.RunCommand

	return func() {
		cmdTimeout = originalTimeout
		vpnBinaryCandidates = originalCandidates
		pathStat = originalPathStat
		runCommand = originalRunCommand
	}
}
