package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseIPOrPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "Single IPv4 without mask",
			input:    "1.1.1.1",
			expected: "1.1.1.1/32",
			wantErr:  false,
		},
		{
			name:     "Single IPv4 with /32 mask",
			input:    "1.1.1.1/32",
			expected: "1.1.1.1/32",
			wantErr:  false,
		},
		{
			name:     "Single IPv4 with whitespace and trailing CRLF",
			input:    "  1.1.1.1/32 \r\n",
			expected: "1.1.1.1/32",
			wantErr:  false,
		},
		{
			name:     "Single IPv4 without mask with whitespace",
			input:    "\t 1.1.1.1 \n",
			expected: "1.1.1.1/32",
			wantErr:  false,
		},
		{
			name:     "IPv4 CIDR /24",
			input:    "1.0.0.0/24",
			expected: "1.0.0.0/24",
			wantErr:  false,
		},
		{
			name:     "IPv4 CIDR with unmasked host bits",
			input:    "1.1.1.1/24",
			expected: "1.1.1.0/24",
			wantErr:  false,
		},
		{
			name:     "IPv4 host:port format",
			input:    "1.1.1.1:443",
			expected: "1.1.1.1/32",
			wantErr:  false,
		},
		{
			name:     "Single IPv6 without mask",
			input:    "2606:4700::6810:85e5",
			expected: "2606:4700::6810:85e5/128",
			wantErr:  false,
		},
		{
			name:     "Single IPv6 with /128 mask",
			input:    "2606:4700::6810:85e5/128",
			expected: "2606:4700::6810:85e5/128",
			wantErr:  false,
		},
		{
			name:     "IPv6 host:port format",
			input:    "[2606:4700::1]:8443",
			expected: "2606:4700::1/128",
			wantErr:  false,
		},
		{
			name:     "IPv6 CIDR /48",
			input:    "2400:cb00::/48",
			expected: "2400:cb00::/48",
			wantErr:  false,
		},
		{
			name:     "UTF-8 BOM prefix",
			input:    "\ufeff1.1.1.1",
			expected: "1.1.1.1/32",
			wantErr:  false,
		},
		{
			name:    "Empty string",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "Invalid string",
			input:   "not.an.ip.address",
			wantErr: true,
		},
		{
			name:    "Invalid CIDR mask",
			input:   "1.1.1.1/99",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := parseIPOrPrefix(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseIPOrPrefix(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && prefix.String() != tt.expected {
				t.Errorf("parseIPOrPrefix(%q) = %q, expected %q", tt.input, prefix.String(), tt.expected)
			}
		})
	}
}

func TestIsSingleIP(t *testing.T) {
	cases := map[string]bool{
		"1.1.1.1":                  true,
		"1.1.1.1/32":               true,
		"1.1.1.0/24":               false,
		"2606:4700::1":             true,
		"2606:4700::1/128":         true,
		"2400:cb00::/48":           false,
		"invalid":                  false,
		"":                         false,
	}

	for input, expected := range cases {
		if got := isSingleIP(input); got != expected {
			t.Errorf("isSingleIP(%q) = %v, want %v", input, got, expected)
		}
	}
}

func TestIsAllSingleIPs(t *testing.T) {
	if !isAllSingleIPs([]string{"1.1.1.1", "8.8.8.8/32", "2606:4700::1"}) {
		t.Errorf("expected true for all single IPs")
	}
	if isAllSingleIPs([]string{"1.1.1.1", "1.0.0.0/24"}) {
		t.Errorf("expected false when subnet is present")
	}
	if isAllSingleIPs([]string{"# comment", ""}) {
		t.Errorf("expected false for empty list")
	}
}

func TestGenIPsFromCIDR_SingleIP(t *testing.T) {
	t.Run("Accept 1.1.1.1 without mask", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "1.1.1.1", 24, nil, nil)
		if len(ips) != 1 || ips[0] != "1.1.1.1" {
			t.Fatalf("expected [1.1.1.1], got %v", ips)
		}
	})

	t.Run("Accept 1.1.1.1/32 with mask", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "1.1.1.1/32", 24, nil, nil)
		if len(ips) != 1 || ips[0] != "1.1.1.1" {
			t.Fatalf("expected [1.1.1.1], got %v", ips)
		}
	})

	t.Run("Boundary 0.0.0.0", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "0.0.0.0", 24, nil, nil)
		if len(ips) != 1 || ips[0] != "0.0.0.0" {
			t.Fatalf("expected [0.0.0.0], got %v", ips)
		}
	})

	t.Run("Boundary 255.255.255.255/32 without infinite loop", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "255.255.255.255/32", 24, nil, nil)
		if len(ips) != 1 || ips[0] != "255.255.255.255" {
			t.Fatalf("expected [255.255.255.255], got %v", ips)
		}
	})

	t.Run("CIDR /30 gives 4 IPs", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "192.168.1.0/30", 24, nil, nil)
		expected := []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
		if !slices.Equal(ips, expected) {
			t.Fatalf("expected %v, got %v", expected, ips)
		}
	})

	t.Run("IgnoreRange with single IP", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "1.1.1.1", 24, []string{"1.1.1.1"}, nil)
		if len(ips) != 0 {
			t.Fatalf("expected 0 IPs, got %v", ips)
		}

		ips = make([]string, 0)
		GenIPsFromCIDR(&ips, "1.1.1.1/32", 24, []string{"1.1.1.1/32"}, nil)
		if len(ips) != 0 {
			t.Fatalf("expected 0 IPs, got %v", ips)
		}

		ips = make([]string, 0)
		GenIPsFromCIDR(&ips, "1.1.1.1", 24, []string{"1.1.1.2"}, nil)
		if len(ips) != 1 || ips[0] != "1.1.1.1" {
			t.Fatalf("expected [1.1.1.1], got %v", ips)
		}
	})

	t.Run("AllowRange with single IP filtering CIDR", func(t *testing.T) {
		ips := make([]string, 0)
		// Input is /24, but allowRange only permits 1.1.1.1
		GenIPsFromCIDR(&ips, "1.1.1.0/24", 24, nil, []string{"1.1.1.1"})
		if len(ips) != 1 || ips[0] != "1.1.1.1" {
			t.Fatalf("expected only [1.1.1.1], got %v", ips)
		}
	})

	t.Run("Empty or comment lines skipped", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPsFromCIDR(&ips, "", 24, nil, nil)
		GenIPsFromCIDR(&ips, "   ", 24, nil, nil)
		GenIPsFromCIDR(&ips, "# this is a comment", 24, nil, nil)
		GenIPsFromCIDR(&ips, "// another comment", 24, nil, nil)
		if len(ips) != 0 {
			t.Fatalf("expected 0 IPs, got %v", ips)
		}
	})
}

func TestGenIPs_DirectInputAndFile(t *testing.T) {
	t.Run("Direct single IP as path", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPs(&ips, "1.1.1.1", nil, nil)
		if len(ips) != 1 || ips[0] != "1.1.1.1" {
			t.Fatalf("expected [1.1.1.1], got %v", ips)
		}
	})

	t.Run("Direct single IP/32 as path", func(t *testing.T) {
		ips := make([]string, 0)
		GenIPs(&ips, "1.1.1.1/32", nil, nil)
		if len(ips) != 1 || ips[0] != "1.1.1.1" {
			t.Fatalf("expected [1.1.1.1], got %v", ips)
		}
	})

	t.Run("File with mixed single IPs and CIDRs", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "test_ips.txt")

		content := "\ufeff# IP list header\n1.1.1.1\r\n\r\n1.0.0.1/32\n// comment\n8.8.8.8\n\n"
		if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		ips := make([]string, 0)
		GenIPs(&ips, filePath, nil, nil)
		expected := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8"}
		if !slices.Equal(ips, expected) {
			t.Fatalf("expected %v, got %v", expected, ips)
		}
	})
}

func TestRandomIPv6FromCIDR(t *testing.T) {
	t.Run("Single IPv6 without mask", func(t *testing.T) {
		ip, err := randomIPv6FromCIDR("2606:4700::6810:85e5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := net.ParseIP("2606:4700::6810:85e5")
		if !ip.Equal(expected) {
			t.Fatalf("expected %v, got %v", expected, ip)
		}
	})

	t.Run("Single IPv6 with /128 mask", func(t *testing.T) {
		ip, err := randomIPv6FromCIDR("2606:4700::6810:85e5/128")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := net.ParseIP("2606:4700::6810:85e5")
		if !ip.Equal(expected) {
			t.Fatalf("expected %v, got %v", expected, ip)
		}
	})

	t.Run("IPv6 CIDR /48 generates valid IP in range", func(t *testing.T) {
		cidr := "2400:cb00:4::/48"
		_, ipNet, _ := net.ParseCIDR(cidr)
		ip, err := randomIPv6FromCIDR(cidr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ipNet.Contains(ip) {
			t.Fatalf("generated IP %v not in CIDR %s", ip, cidr)
		}
	})

	t.Run("Invalid IPv6 returns error", func(t *testing.T) {
		_, err := randomIPv6FromCIDR("invalid-ip")
		if err == nil {
			t.Fatalf("expected error for invalid IPv6")
		}
	})
}

func TestNetipPrefixContainsLogic(t *testing.T) {
	// Verify exact netip loop behavior for single IP
	prefix := netip.MustParsePrefix("1.1.1.1/32")
	count := 0
	for ip := prefix.Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
		count++
	}
	if count != 1 {
		t.Fatalf("expected 1 iteration, got %d", count)
	}
}

func TestStripComment(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"1.1.1.1 # Cloudflare DNS", "1.1.1.1"},
		{"1.1.1.1/32 // test inline", "1.1.1.1/32"},
		{"1.1.1.1 ; semicolon comment", "1.1.1.1"},
		{"# Full line comment", ""},
		{"// Another full line", ""},
		{"; Semicolon full line", ""},
		{"   1.1.1.1   \r\n", "1.1.1.1"},
	}

	for _, c := range cases {
		got := stripComment(c.input)
		if got != c.expected {
			t.Errorf("stripComment(%q) = %q, expected %q", c.input, got, c.expected)
		}
	}
}

func TestParseIPOrPrefixWithPort(t *testing.T) {
	cases := []struct {
		input        string
		expectedPfx  string
		expectedPort int
		wantErr      bool
	}{
		{"1.1.1.1", "1.1.1.1/32", 0, false},
		{"1.1.1.1/32", "1.1.1.1/32", 0, false},
		{"1.1.1.1:8443", "1.1.1.1/32", 8443, false},
		{"1.1.1.1/32:8443", "1.1.1.1/32", 8443, false},
		{"[2606:4700::1]", "2606:4700::1/128", 0, false},
		{"[2606:4700::1]:8443", "2606:4700::1/128", 8443, false},
		{"https://1.1.1.1/", "1.1.1.1/32", 0, false},
		{"http://1.1.1.1:8080/", "1.1.1.1/32", 8080, false},
		{`"1.1.1.1"`, "1.1.1.1/32", 0, false},
		{"'1.1.1.1/32'", "1.1.1.1/32", 0, false},
		{"1.1.1.1 # cloudflare", "1.1.1.1/32", 0, false},
		{"1.1.1.1/32 // test", "1.1.1.1/32", 0, false},
		{"2606:4700::1 ; ip", "2606:4700::1/128", 0, false},
		{"not-an-ip", "", 0, true},
		{"", "", 0, true},
	}

	for _, c := range cases {
		pfx, port, err := parseIPOrPrefixWithPort(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseIPOrPrefixWithPort(%q) expected error, got nil", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseIPOrPrefixWithPort(%q) unexpected error: %v", c.input, err)
			continue
		}
		if pfx.String() != c.expectedPfx {
			t.Errorf("parseIPOrPrefixWithPort(%q) prefix = %s, expected %s", c.input, pfx.String(), c.expectedPfx)
		}
		if port != c.expectedPort {
			t.Errorf("parseIPOrPrefixWithPort(%q) port = %d, expected %d", c.input, port, c.expectedPort)
		}
	}
}

func TestParseRange_And_RandomRange(t *testing.T) {
	// Test single number
	a, b := parseRange("32")
	if a != 32 || b != 32 {
		t.Fatalf("parseRange(\"32\") expected (32, 32), got (%d, %d)", a, b)
	}
	rnd := randomRange("32")
	if rnd != 32 {
		t.Fatalf("randomRange(\"32\") expected 32, got %d", rnd)
	}

	// Test standard range
	a, b = parseRange("24-65")
	if a != 24 || b != 65 {
		t.Fatalf("parseRange(\"24-65\") expected (24, 65), got (%d, %d)", a, b)
	}
	for range 100 {
		val := randomRange("24-65")
		if val < 24 || val > 65 {
			t.Fatalf("randomRange(\"24-65\") returned out of range value: %d", val)
		}
	}

	// Test inverted bounds swapped safely
	a, b = parseRange("65-24")
	if a != 24 || b != 65 {
		t.Fatalf("parseRange(\"65-24\") expected (24, 65), got (%d, %d)", a, b)
	}

	// Test empty string
	a, b = parseRange("")
	if a != 0 || b != 0 {
		t.Fatalf("parseRange(\"\") expected (0, 0), got (%d, %d)", a, b)
	}
	rnd = randomRange("")
	if rnd != 0 {
		t.Fatalf("randomRange(\"\") expected 0, got %d", rnd)
	}
}

func TestGenIPs_CommaSeparated(t *testing.T) {
	ips := make([]string, 0)
	GenIPs(&ips, "1.1.1.1, 1.0.0.1; 8.8.8.8/32", nil, nil)
	expected := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8"}
	if !slices.Equal(ips, expected) {
		t.Fatalf("expected %v, got %v", expected, ips)
	}
}

func TestGenIPs_FileWithInlineComments(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test_comments.txt")
	content := "1.1.1.1 # Cloudflare 1\n1.0.0.1/32 // Cloudflare 2\n8.8.8.8 ; Google DNS\n"
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	ips := make([]string, 0)
	GenIPs(&ips, filePath, nil, nil)
	expected := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8"}
	if !slices.Equal(ips, expected) {
		t.Fatalf("expected %v, got %v", expected, ips)
	}
}

func TestResolveFilePath(t *testing.T) {
	// Test existing file in current dir
	got := resolveFilePath("conf.json")
	if got != "conf.json" {
		t.Errorf("resolveFilePath(\"conf.json\") = %s, expected conf.json", got)
	}

	// Test non-existent file returns original string
	gotMissing := resolveFilePath("non_existent_file_xyz.txt")
	if gotMissing != "non_existent_file_xyz.txt" {
		t.Errorf("resolveFilePath for missing file returned %s", gotMissing)
	}
}

