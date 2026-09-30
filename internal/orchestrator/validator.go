package orchestrator

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	// Domain / Hostname regex (RFC 1123)
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
)

// TargetType identifies the kind of target specified
type TargetType string

const (
	TargetIPv4   TargetType = "IPv4"
	TargetIPv6   TargetType = "IPv6"
	TargetCIDR   TargetType = "CIDR"
	TargetDomain TargetType = "Domain"
)

// TargetInfo contains parsed and verified target metadata
type TargetInfo struct {
	Original string     `json:"original"`
	Type     TargetType `json:"type"`
	Clean    string     `json:"clean"`
}

// ValidateTarget checks and validates if the target is a valid IP, CIDR or domain name.
func ValidateTarget(input string) (*TargetInfo, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("цель сканирования не может быть пустой")
	}

	// Prevent argument injection and shell metacharacters
	if strings.ContainsAny(trimmed, " \t\r\n;&|`$><'\"\\") {
		return nil, fmt.Errorf("цель содержит недопустимые символы")
	}

	// 1. Check if single IP (IPv4 or IPv6)
	ip := net.ParseIP(trimmed)
	if ip != nil {
		if ip.To4() != nil {
			return &TargetInfo{
				Original: trimmed,
				Type:     TargetIPv4,
				Clean:    ip.String(),
			}, nil
		}
		return &TargetInfo{
			Original: trimmed,
			Type:     TargetIPv6,
			Clean:    ip.String(),
		}, nil
	}

	// 2. Check if CIDR notation
	if strings.Contains(trimmed, "/") {
		_, ipNet, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, fmt.Errorf("некорректный формат CIDR подсети: %w", err)
		}
		return &TargetInfo{
			Original: trimmed,
			Type:     TargetCIDR,
			Clean:    ipNet.String(),
		}, nil
	}

	// 3. Check if Domain / Hostname
	if domainRegex.MatchString(trimmed) {
		return &TargetInfo{
			Original: trimmed,
			Type:     TargetDomain,
			Clean:    strings.ToLower(trimmed),
		}, nil
	}

	return nil, fmt.Errorf("недопустимый формат цели '%s': укажите валидный IP-адрес, CIDR подсеть или доменное имя", trimmed)
}
