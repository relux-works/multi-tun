package model

import "fmt"

type Profile struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	URI         string            `json:"uri"`
	Protocol    string            `json:"protocol"`
	UUID        string            `json:"uuid"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Security    string            `json:"security"`
	Network     string            `json:"network"`
	ServiceName string            `json:"service_name,omitempty"`
	Authority   string            `json:"authority,omitempty"`
	SNI         string            `json:"sni,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
	ShortID     string            `json:"short_id,omitempty"`
	Flow        string            `json:"flow,omitempty"`
	Query       map[string]string `json:"query,omitempty"`
}

func (p Profile) Endpoint() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

func (p Profile) DisplayName() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Endpoint()
}
