package madns

import (
	"context"
	"net"
	"testing"
)

func TestLibP2PDirectIPv4(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv4: 192.0.2.1 → 192-0-2-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "192-0-2-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("192.0.2.1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6Standard(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 standard: 2001:db8::1 → 2001-db8-0-0-0-0-0-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8-0-0-0-0-0-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6Condensed(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 condensed: 2001:db8::1 → 2001-db8--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6LeadingZeros(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 leading zeros: ::1 → 0--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "0--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("::1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6TrailingZeros(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 trailing zeros: 2001:db8:: → 2001-db8--0.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8--0.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6TrailingZerosWithoutZero(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 trailing zeros without explicit zero: 2001:db8:: → 2001-db8--.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	// WARNING: DNS names ending with -- may not be valid according to RFC 1123
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8--.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6LeadingZerosWithoutZero(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 leading zeros without explicit zero: ::1 → --1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	// WARNING: DNS names starting with -- may not be valid according to RFC 1123
	addrs, err := resolver.LookupIPAddr(ctx, "--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("::1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6CondensedWith0(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 condensed with 0: 2001:db8::1:2 → 2001-db8--1-2.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8--1-2.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::1:2")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6CondensedWithout0(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 condensed without 0: 2001:db8:85a3::8a2e → 2001-db8-85a3--8a2e.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8-85a3--8a2e.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8:85a3::8a2e")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6Priority(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 priority: IPv6 parsing is tried first, but may fail and fallback to IPv4
	// Case: "10-0-0-1" - IPv6 "10:0:0:1::" is invalid, so falls back to IPv4 "10.0.0.1"
	addrs, err := resolver.LookupIPAddr(ctx, "10-0-0-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("10.0.0.1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectIPv6PrioritySuccess(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test IPv6 priority success: valid IPv6 with hex digits (clearly not IPv4)
	// Case: "2001-db8--a-b" - contains hex digits and ::, so IPv6 takes priority and succeeds
	addrs, err := resolver.LookupIPAddr(ctx, "2001-db8--a-b.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::a:b")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestLibP2PDirectInvalidFormat(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test invalid format (no peer ID) - this should NOT match p2p-forge pattern and fallback to normal DNS
	// Since MockResolver returns empty results (not errors), this will return empty results
	addrs, err := resolver.LookupIPAddr(ctx, "192-0-2-1.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("Expected 0 addresses, got %d", len(addrs))
	}

	// Test invalid IP encoding - this should match p2p-forge pattern but fail IP decoding, then fallback to normal DNS
	addrs, err = resolver.LookupIPAddr(ctx, "invalid-ip.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("Expected 0 addresses, got %d", len(addrs))
	}
}

func TestLibP2PDirectFallback(t *testing.T) {
	// Test fallback to normal DNS resolution
	mock := &MockResolver{
		IP: map[string][]net.IPAddr{
			"fallback.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct": {
				{IP: net.ParseIP("192.0.2.1")},
			},
		},
	}
	resolver := &Resolver{def: mock}
	ctx := context.Background()

	// This should fail synthetic resolution and fallback to normal DNS
	addrs, err := resolver.LookupIPAddr(ctx, "fallback.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct")
	if err != nil {
		t.Fatalf("Expected no error with fallback, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("192.0.2.1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestP2PForgeCustomSuffix(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	// Test with custom suffix: .example.com
	addrs, err := resolver.LookupIPAddr(ctx, "192-0-2-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.example.com")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("192.0.2.1")
	if !addrs[0].IP.Equal(expected) {
		t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
	}
}

func TestP2PForgeMultipleSuffixes(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	tests := []struct {
		name   string
		domain string
		ip     string
	}{
		{
			name:   "custom.direct with base36 CIDv1",
			domain: "2001-db8--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.custom.direct",
			ip:     "2001:db8::1",
		},
		{
			name:   "p2p.local with base36 CIDv1",
			domain: "fe80--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.p2p.local",
			ip:     "fe80::1",
		},
		{
			name:   "peer.example.org with base36 CIDv1",
			domain: "203-0-113-42.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.peer.example.org",
			ip:     "203.0.113.42",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrs, err := resolver.LookupIPAddr(ctx, test.domain)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			if len(addrs) != 1 {
				t.Fatalf("Expected 1 address, got %d", len(addrs))
			}
			expected := net.ParseIP(test.ip)
			if !addrs[0].IP.Equal(expected) {
				t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
			}
		})
	}
}

func TestLibp2pPeerIDValidation(t *testing.T) {
	tests := []struct {
		peerID   string
		expected bool
		desc     string
	}{
		{
			peerID:   "k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r",
			expected: true,
			desc:     "valid base36 CIDv1 (Ed25519)",
		},
		{
			peerID:   "k2k4r8oao3a13ig746677ovbb1s6hnvgksy42n2u8vo0o0m3xogyxhju",
			expected: true,
			desc:     "valid base36 CIDv1 (RSA)",
		},
		{
			peerID:   "QmTzQ1JRkWErjk39mryYw2WVaphAZNAREyMchXzYQ59eTR",
			expected: false,
			desc:     "base58 CIDv0 not supported in DNS",
		},
		{
			peerID:   "12D3KooWEy2U7rNW8sbEF8dz2vDj5fFzVWfgBsAj7nxNqvRxp1FR",
			expected: false,
			desc:     "base58 CIDv1 not supported in DNS",
		},
		{
			peerID:   "kshort",
			expected: false,
			desc:     "too short",
		},
		{
			peerID:   "k51invalid",
			expected: false,
			desc:     "wrong base36 prefix",
		},
		{
			peerID:   "regular-string",
			expected: false,
			desc:     "not a peer ID",
		},
		{
			peerID:   "k51qzi5uqu5INVALID",
			expected: false,
			desc:     "invalid base36 characters (uppercase)",
		},
		{
			peerID:   "k2jmtxw8rjh1z69c6not3wtdxb0u3urbzhyll1t9jg6ox26dhi5sfi1m",
			expected: false,
			desc:     "valid CID but wrong codec (not libp2p-key)",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result := isLibp2pPeerID(test.peerID)
			if result != test.expected {
				t.Fatalf("Expected %v for %s, got %v", test.expected, test.peerID, result)
			}
		})
	}
}

func TestP2PForgeDomainParsing(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
		desc     string
	}{
		{
			domain:   "192-0-2-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: true,
			desc:     "valid p2p-forge pattern with base36 CIDv1",
		},
		{
			domain:   "192-0-2-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.example.com",
			expected: true,
			desc:     "valid p2p-forge pattern with base36 CIDv1",
		},
		{
			domain:   "example.com",
			expected: false,
			desc:     "regular domain",
		},
		{
			domain:   "192-0-2-1.regular-subdomain.example.com",
			expected: false,
			desc:     "no peer ID",
		},
		{
			domain:   "192-0-2-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r",
			expected: false,
			desc:     "insufficient parts (no suffix)",
		},
		{
			domain:   "example.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.com",
			expected: true,
			desc:     "peer ID in correct position (but weird IP encoding)",
		},
		{
			domain:   "192-0-2-1.subdomain.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.com",
			expected: false,
			desc:     "peer ID in wrong position (third instead of second)",
		},
		{
			domain:   "192-0-2-1.kshort.example.com",
			expected: false,
			desc:     "invalid peer ID (too short)",
		},
		{
			domain:   "192-0-2-1.k51invalid.example.com",
			expected: false,
			desc:     "invalid peer ID (wrong base36 prefix)",
		},
		{
			domain:   "192-0-2-1.QmInvalid.example.com",
			expected: false,
			desc:     "invalid peer ID (base58 not supported in DNS)",
		},
		{
			domain:   "192-0-2-1.k2jmtxw8rjh1z69c6not3wtdxb0u3urbzhyll1t9jg6ox26dhi5sfi1m.example.com",
			expected: false,
			desc:     "valid CID but wrong codec (not libp2p-key)",
		},
		{
			domain:   "short.domain",
			expected: false,
			desc:     "too short domain (length optimization)",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result := parseP2PForgeDomain(test.domain)
			isValid := result != nil
			if isValid != test.expected {
				t.Fatalf("Expected %v for %s, got %v", test.expected, test.domain, isValid)
			}
		})
	}
}

func TestLibP2PDirectComplexCases(t *testing.T) {
	resolver := &Resolver{def: &MockResolver{}}
	ctx := context.Background()

	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "IPv4 TEST-NET-1",
			domain:   "192-0-2-255.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "192.0.2.255",
		},
		{
			name:     "IPv4 TEST-NET-2",
			domain:   "198-51-100-1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "198.51.100.1",
		},
		{
			name:     "IPv4 TEST-NET-3",
			domain:   "203-0-113-42.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "203.0.113.42",
		},
		{
			name:     "IPv6 RFC3849 doc prefix",
			domain:   "2001-db8-85a3-0000-0000-8a2e-0370-7334.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:     "IPv6 RFC3849 condensed",
			domain:   "2001-db8--8a2e-370-7334.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "2001:db8::8a2e:370:7334",
		},
		{
			name:     "IPv6 link-local",
			domain:   "fe80--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "fe80::1",
		},
		{
			name:     "IPv6 loopback",
			domain:   "0--1.k51qzi5uqu5dj2c294cab64yiq2ri684kc5sr9odfhoo84osl4resldwfy8u5r.libp2p.direct",
			expected: "::1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrs, err := resolver.LookupIPAddr(ctx, test.domain)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			if len(addrs) != 1 {
				t.Fatalf("Expected 1 address, got %d", len(addrs))
			}
			expected := net.ParseIP(test.expected)
			if !addrs[0].IP.Equal(expected) {
				t.Fatalf("Expected %s, got %s", expected, addrs[0].IP)
			}
		})
	}
}

func TestDecodeIPv4(t *testing.T) {
	tests := []struct {
		encoded  string
		expected string
		valid    bool
	}{
		{"192-0-2-1", "192.0.2.1", true},
		{"198-51-100-1", "198.51.100.1", true},
		{"203-0-113-42", "203.0.113.42", true},
		{"0-0-0-0", "0.0.0.0", true},
		{"invalid", "", false},
		{"192-0-2", "", false},
		{"192-0-2-1-5", "", false},
	}

	for _, test := range tests {
		t.Run(test.encoded, func(t *testing.T) {
			result := decodeIPv4(test.encoded)
			if test.valid {
				if result == nil {
					t.Fatalf("Expected valid IP, got nil")
				}
				expected := net.ParseIP(test.expected)
				if !result.Equal(expected) {
					t.Fatalf("Expected %s, got %s", expected, result)
				}
			} else {
				if result != nil {
					t.Fatalf("Expected nil, got %s", result)
				}
			}
		})
	}
}

func TestDecodeIPv6(t *testing.T) {
	tests := []struct {
		encoded  string
		expected string
		valid    bool
	}{
		{"2001-db8--1", "2001:db8::1", true},
		{"2001-db8-85a3--8a2e", "2001:db8:85a3::8a2e", true},
		{"0--1", "::1", true},
		{"--1", "::1", true},
		{"2001-db8--0", "2001:db8::", true},
		{"2001-db8--", "2001:db8::", true},
		{"fe80-0-0-0-0-0-0-1", "fe80::1", true},
		{"2001-0db8-85a3-0000-0000-8a2e-0370-7334", "2001:db8:85a3::8a2e:370:7334", true},
		{"invalid", "", false},
		{"192-0-2-1", "", false}, // This should be treated as IPv4, not IPv6
	}

	for _, test := range tests {
		t.Run(test.encoded, func(t *testing.T) {
			result := decodeIPv6(test.encoded)
			if test.valid {
				if result == nil {
					t.Fatalf("Expected valid IP, got nil")
				}
				expected := net.ParseIP(test.expected)
				if !result.Equal(expected) {
					t.Fatalf("Expected %s, got %s", expected, result)
				}
			} else {
				if result != nil {
					t.Fatalf("Expected nil, got %s", result)
				}
			}
		})
	}
}
