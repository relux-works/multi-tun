package diag

import "strings"

type KernelRoute struct {
	TargetIP    string `json:"target_ip"`
	RouteTo     string `json:"route_to,omitempty"`
	Destination string `json:"destination,omitempty"`
	Mask        string `json:"mask,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Error       string `json:"error,omitempty"`
}

func ParseRouteGet(targetIP, output string) KernelRoute {
	r := KernelRoute{TargetIP: targetIP}
	for _, line := range strings.Split(output, "\n") {
		key, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(key) {
		case "route to":
			r.RouteTo = v
		case "destination":
			r.Destination = v
		case "mask":
			r.Mask = v
		case "gateway":
			r.Gateway = v
		case "interface":
			r.Interface = v
		case "flags":
			r.Flags = v
		}
	}
	if r.Interface == "" {
		r.Error = clean(output, 512)
		if r.Error == "" {
			r.Error = "route lookup returned no interface"
		}
	}
	return r
}
