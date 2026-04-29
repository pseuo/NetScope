package service

import (
	"context"
	"net"
	"strings"
	"time"
)

func IsIP(input string) bool {
	return net.ParseIP(input) != nil
}

func DetectIPVersion(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	if parsed.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func ResolveDomainIPs(domain string) (ipv4s []string, ipv6s []string, err error) {
	return ResolveDomainIPsTimeout(domain, 1500*time.Millisecond)
}

func ResolveDomainIPsTimeout(domain string, timeout time.Duration) (ipv4s []string, ipv6s []string, err error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range ips {
		ip := addr.IP
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip.String())
		} else {
			ipv6s = append(ipv6s, ip.String())
		}
	}
	return
}

func ReverseLookup(ip string) string {
	return ReverseLookupTimeout(ip, 1500*time.Millisecond)
}

func ReverseLookupTimeout(ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
