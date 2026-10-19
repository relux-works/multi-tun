package vpncorecli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os/exec"

	"multi-tun/desktop/internal/core/ifaceaudit"
)

var (
	ifconfigOutputVPNCoreCLI = func() ([]byte, error) {
		return exec.Command("/sbin/ifconfig").Output()
	}
	routeOutputVPNCoreCLI = func() ([]byte, error) {
		return exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").Output()
	}
	collectInterfaceClaimsVPNCoreCLI = ifaceaudit.CollectClaims
)

func (a *App) runInterfaces(args []string) int {
	fs := flag.NewFlagSet("interfaces", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	jsonOutput := fs.Bool("json", false, "Print the interface audit as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "interfaces refuses positional arguments")
		return 2
	}

	ifconfigRaw, err := ifconfigOutputVPNCoreCLI()
	if err != nil {
		fmt.Fprintf(a.stderr, "interfaces failed: read interface state: %v\n", err)
		return 1
	}
	interfaces, err := ifaceaudit.ParseIfconfig(ifconfigRaw)
	if err != nil {
		fmt.Fprintf(a.stderr, "interfaces failed: %v\n", err)
		return 1
	}

	routeRaw, err := routeOutputVPNCoreCLI()
	if err != nil {
		fmt.Fprintf(a.stderr, "interfaces failed: read route state: %v\n", err)
		return 1
	}
	defaultRoutes, err := ifaceaudit.ParseDefaultRoutes(routeRaw)
	if err != nil {
		fmt.Fprintf(a.stderr, "interfaces failed: %v\n", err)
		return 1
	}

	claims := collectInterfaceClaimsVPNCoreCLI()
	report := ifaceaudit.Classify(interfaces, claims.Claims, defaultRoutes)
	report.Issues = append(report.Issues, claims.Issues...)
	if *jsonOutput {
		encoder := json.NewEncoder(a.stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(a.stderr, "interfaces failed: encode JSON: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprint(a.stdout, ifaceaudit.RenderText(report))
	return 0
}
