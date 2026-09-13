package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// stripComment removes comments starting with #, //, or ; and trims whitespace.
// For //, only comments preceded by whitespace or at line start are stripped so that URLs like https:// are preserved.
func stripComment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, ";") {
		return ""
	}
	for _, sep := range []string{"#", " //", "\t//", ";"} {
		if idx := strings.Index(s, sep); idx != -1 {
			s = s[:idx]
		}
	}
	return strings.TrimSpace(s)
}

// parseIPOrPrefixWithPort parses an input string as either:
// - A single IP address, e.g. "1.1.1.1", "2400:cb00::1", "[2400:cb00::1]"
// - A single IP with mask, e.g. "1.1.1.1/32", "2400:cb00::1/128"
// - A CIDR prefix, e.g. "1.0.0.0/24", "2400:cb00::/48"
// - An IP with optional port, e.g. "1.1.1.1:443", "[2606:4700::1]:8443", "1.1.1.1/32:443"
// - URL formats or quoted strings, e.g. "https://1.1.1.1/"
// It returns the normalized netip.Prefix, the extracted port (0 if none), and any error.
func parseIPOrPrefixWithPort(s string) (netip.Prefix, int, error) {
	s = strings.TrimPrefix(s, "\ufeff")
	s = stripComment(s)
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, 0, errors.New("empty IP or CIDR string")
	}

	// Trim surrounding quotes
	s = strings.Trim(s, `"'`+"`")

	// Strip URL schemes and trailing slashes if present
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")

	port := 0
	// Check for host:port (e.g. "1.1.1.1:443", "[2606:4700::1]:443", or "1.1.1.1/32:443")
	if host, portStr, err := net.SplitHostPort(s); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = p
			s = host
		}
	}

	// Strip bracket wrapper for IPv6 without port (e.g. "[2606:4700::1]")
	s = strings.Trim(s, "[]")

	// If it contains a slash, parse as prefix
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, 0, fmt.Errorf("invalid CIDR prefix '%s': %w", s, err)
		}
		return prefix.Masked(), port, nil
	}

	// Parse as a single IP address
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("invalid IP address '%s': %w", s, err)
	}

	// Convert single IP to /32 (IPv4) or /128 (IPv6)
	return netip.PrefixFrom(addr, addr.BitLen()), port, nil
}

// parseIPOrPrefix parses an input string as either a CIDR prefix or single IP.
// It returns the normalized netip.Prefix.
func parseIPOrPrefix(s string) (netip.Prefix, error) {
	prefix, _, err := parseIPOrPrefixWithPort(s)
	return prefix, err
}

// isSingleIP returns true if the given string represents a single IP address
// (e.g. "1.1.1.1", "1.1.1.1/32", "2606:4700::1", "2606:4700::1/128").
func isSingleIP(s string) bool {
	prefix, err := parseIPOrPrefix(s)
	if err != nil {
		return false
	}
	return prefix.IsSingleIP()
}

// isAllSingleIPs checks if all non-empty lines in list represent single IP addresses.
func isAllSingleIPs(list []string) bool {
	validCount := 0
	for _, item := range list {
		item = stripComment(item)
		if item == "" {
			continue
		}
		if !isSingleIP(item) {
			return false
		}
		validCount++
	}
	return validCount > 0
}

func GenIPsFromCIDR(ips *[]string, netCIDR string, subnetMaskSize int, ignoreRange []string, allowRange []string) {
	netCIDR = stripComment(netCIDR)
	if netCIDR == "" {
		return
	}

	prefix, err := parseIPOrPrefix(netCIDR)
	if err != nil {
		exitOnError(fmt.Errorf("invalid CIDR or IP '%s': %w", netCIDR, err))
		return
	}

	for _, ignorePrefixStr := range ignoreRange {
		ignorePrefixStr = stripComment(ignorePrefixStr)
		if ignorePrefixStr == "" {
			continue
		}
		ignorePrefix, err := parseIPOrPrefix(ignorePrefixStr)
		if err != nil {
			exitOnError(fmt.Errorf("invalid ignoreRange '%s': %w", ignorePrefixStr, err))
			return
		}
		if ignorePrefix.Overlaps(prefix) {
			return
		}
	}

	// Guard against expanding large IPv6 CIDR subnets linearly in memory
	if prefix.Addr().Is6() && !prefix.IsSingleIP() {
		exitOnError(fmt.Errorf("cannot linearly expand IPv6 subnet '%s'; IPv6 subnets require IpVersion 6 with RandomScan", netCIDR))
		return
	}

	if len(allowRange) > 0 {
		for _, allowPrefixStr := range allowRange {
			allowPrefixStr = stripComment(allowPrefixStr)
			if allowPrefixStr == "" {
				continue
			}
			allowPrefix, err := parseIPOrPrefix(allowPrefixStr)
			if err != nil {
				exitOnError(fmt.Errorf("invalid allowRange '%s': %w", allowPrefixStr, err))
				return
			}
			if allowPrefix.Overlaps(prefix) {
				for ip := prefix.Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
					if allowPrefix.Contains(ip) {
						*ips = append(*ips, ip.String())
					}
				}
				break // Avoid duplicate additions if multiple allow ranges match
			}
		}
	} else {
		for ip := prefix.Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
			*ips = append(*ips, ip.String())
		}
	}
}

func GenIPs(ips *[]string, ipv4FilePath string, ignoreRange []string, allowRange []string) {
	ipv4FilePath = strings.TrimSpace(ipv4FilePath)
	if ipv4FilePath == "" {
		exitOnError(errors.New("empty IP list path"))
		return
	}

	// 1. If ipv4FilePath itself is a valid single IP or CIDR (e.g. user specified "1.1.1.1" or "1.1.1.1/32"),
	// generate IPs directly from it without trying to open a file.
	if prefix, err := parseIPOrPrefix(ipv4FilePath); err == nil {
		GenIPsFromCIDR(ips, prefix.String(), 24, ignoreRange, allowRange)
		return
	}

	// 2. Check if it is a comma- or semicolon-separated list of IPs/CIDRs (e.g. "1.1.1.1, 1.0.0.1")
	if strings.ContainsAny(ipv4FilePath, ",;") {
		parts := strings.FieldsFunc(ipv4FilePath, func(r rune) bool {
			return r == ',' || r == ';'
		})
		allParsed := true
		for _, part := range parts {
			part = stripComment(part)
			if part == "" {
				continue
			}
			if _, err := parseIPOrPrefix(part); err != nil {
				allParsed = false
				break
			}
		}
		if allParsed && len(parts) > 0 {
			for _, part := range parts {
				part = stripComment(part)
				if part == "" {
					continue
				}
				GenIPsFromCIDR(ips, part, 24, ignoreRange, allowRange)
			}
			return
		}
	}

	// 3. Otherwise try reading as a file (checking cwd and executable directory)
	resolvedPath := resolveFilePath(ipv4FilePath)
	file, ipListFileErr := os.ReadFile(resolvedPath)
	if ipListFileErr != nil {
		exitOnError(fmt.Errorf("failed to read IP list file '%s': %w", ipv4FilePath, ipListFileErr))
		return
	}

	content := strings.TrimPrefix(string(file), "\ufeff")
	for line := range strings.Lines(content) {
		line = stripComment(line)
		if line == "" {
			continue
		}
		GenIPsFromCIDR(ips, line, 24, ignoreRange, allowRange)
	}
}

func randomIPv6FromCIDR(cidr string) (net.IP, error) {
	cidr = stripComment(cidr)
	if cidr == "" {
		return nil, errors.New("empty IPv6 CIDR")
	}

	// Check if single IPv6 address without CIDR mask
	if !strings.Contains(cidr, "/") {
		if host, _, err := net.SplitHostPort(cidr); err == nil {
			cidr = host
		}
		cidr = strings.Trim(cidr, "[]")
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", cidr)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("expected IPv6, got IPv4: %s", cidr)
		}
		return ip.To16(), nil
	}

	// If single IPv6 with /128 mask
	if strings.HasSuffix(cidr, "/128") {
		base := strings.TrimSuffix(cidr, "/128")
		base = strings.Trim(base, "[]")
		ip := net.ParseIP(base)
		if ip != nil && ip.To4() == nil {
			return ip.To16(), nil
		}
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	mask := ipNet.Mask
	ip := ipNet.IP.To16()

	prefixLen, _ := mask.Size()
	totalBits := 128
	variableBits := totalBits - prefixLen

	if variableBits <= 0 {
		return ip, nil
	}

	// Generate a random number for the variable part
	max := new(big.Int).Lsh(big.NewInt(1), uint(variableBits))
	randNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	ipInt := new(big.Int).SetBytes(ip)

	ipInt.Or(ipInt, randNum)

	// Convert back to net.IP
	randomIP := make(net.IP, 16)
	ipInt.FillBytes(randomIP)

	return randomIP, nil
}
