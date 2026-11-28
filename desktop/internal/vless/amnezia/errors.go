package amnezia

import (
	"errors"
	"fmt"
	"strings"
)

const (
	DefaultKeychainService  = "tun-wave"
	FallbackKeychainService = "multi-tun"
	DefaultKeychainAccount  = "amnezia/key"
	PlaceholderKey          = "PLACEHOLDER_AMNEZIA_KEY_REPLACE_ME"

	CodeKeyMissing           = "AMNEZIA_KEY_MISSING"
	CodeKeyEmpty             = "AMNEZIA_KEY_EMPTY"
	CodeKeyPlaceholder       = "AMNEZIA_KEY_PLACEHOLDER"
	CodeKeychainAccessDenied = "AMNEZIA_KEYCHAIN_ACCESS_DENIED"
	CodeKeyInvalid           = "AMNEZIA_KEY_INVALID"
	CodeProtocolUnsupported  = "AMNEZIA_PROTOCOL_UNSUPPORTED"
	CodeRegionUnmatched      = "AMNEZIA_REGION_UNMATCHED"
	CodeEngineUnavailable    = "AMNEZIA_ENGINE_UNAVAILABLE"
	CodeGatewayUnimplemented = "AMNEZIA_GATEWAY_UNIMPLEMENTED"
)

// RefusalError carries a deterministic SPEC-005 refusal code and a redacted
// operator-facing diagnostic message. Cause is retained for programmatic
// inspection via Unwrap but omitted from Error() so raw secret payloads cannot
// accidentally leak through low-level error strings.
type RefusalError struct {
	Code    string
	Message string
	Cause   error
}

func NewRefusal(code, message string) *RefusalError {
	return &RefusalError{
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
	}
}

func WrapRefusal(code, message string, cause error) *RefusalError {
	return &RefusalError{
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
		Cause:   cause,
	}
}

func (e *RefusalError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *RefusalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *RefusalError) Is(target error) bool {
	other, ok := target.(*RefusalError)
	if !ok || other == nil {
		return false
	}
	return other.Code != "" && e.Code == other.Code
}

// RefusalCode returns the SPEC-005 refusal code carried by err, or "" if none.
func RefusalCode(err error) string {
	var refusal *RefusalError
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// IsRefusalCode reports whether err carries the specified SPEC-005 refusal code.
func IsRefusalCode(err error, code string) bool {
	return code != "" && RefusalCode(err) == code
}
