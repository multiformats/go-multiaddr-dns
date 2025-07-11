package madns

// This file contains performance optimizations where well-known DNS label conventions
// are resolved statically to avoid unnecessary network I/O.
//
// Currently supports:
//   - p2p-forge protocol domains (deterministic IP address resolution): https://github.com/ipshipyard/p2p-forge

import (
	"context"
	"net"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multicodec"
)

const minLibp2pPeerIDLength = 42 // Conservative minimum per https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md

// minP2PForgeDomain is the minimum possible length for a valid p2p-forge domain
// Format: <ip>.<peerID>.<suffix>
// Shortest IPv4: "0-0-0-0" (7 chars), shortest peerID: 42 chars, shortest suffix: "a" (1 char), dots: 2
const minP2PForgeDomain = 7 + 1 + minLibp2pPeerIDLength + 1 + 1 // 52 characters

// parseP2PForgeDomain checks if a domain follows the p2p-forge pattern
// Format: <encoded-ip>.<peerID>.<suffix>
// Returns the DNS labels if valid, nil otherwise
func parseP2PForgeDomain(domain string) []string {
	// Quick length check to avoid splitting obviously too-short domains
	if len(domain) < minP2PForgeDomain {
		return nil
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 3 { // need at least <ip>.<peerID>.<suffix>
		return nil
	}

	// Check if the second part (index 1) looks like a libp2p peer ID
	peerID := parts[1]
	if !isLibp2pPeerID(peerID) {
		return nil
	}

	return parts
}

// isLibp2pPeerID checks if a string is a valid libp2p peer ID
// by parsing it as a CID and verifying it uses the libp2p-key codec
func isLibp2pPeerID(s string) bool {
	// Only attempt CID parsing if string is long enough to be a valid base36 libp2p peer ID
	if len(s) < minLibp2pPeerIDLength {
		return false
	}

	c, err := cid.Decode(s)
	if err != nil {
		return false
	}

	// Check if the CID uses the libp2p-key codec
	return c.Type() == uint64(multicodec.Libp2pKey)
}

// resolveP2PForge handles p2p-forge domains that encode IP addresses
// according to the p2p-forge protocol specification via synthetic offline resolution.
//
// Domain format: <encoded-ip>.<base36-peerID>.<suffix>
//
// See: https://github.com/ipshipyard/p2p-forge?tab=readme-ov-file#handled-dns-records
func (r *Resolver) resolveP2PForge(ctx context.Context, domain string, parts []string) ([]net.IPAddr, error) {
	// The first part is the encoded IP address
	encodedIP := parts[0]

	// Try IPv6 first (as per spec), then IPv4
	if ip := decodeIPv6(encodedIP); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	if ip := decodeIPv4(encodedIP); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	return nil, &net.DNSError{
		Err:    "invalid IP encoding in p2p-forge domain",
		Name:   domain,
		Server: "",
	}
}

// decodeIPv4 converts hyphens back to dots for IPv4 addresses
// Example: 1-2-3-4 → 1.2.3.4
func decodeIPv4(encoded string) net.IP {
	// Convert hyphens back to dots
	ipStr := strings.ReplaceAll(encoded, "-", ".")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	// Ensure it's actually an IPv4 address
	if ip.To4() == nil {
		return nil
	}
	return ip
}

// decodeIPv6 converts encoded IPv6 addresses back to standard format
// Handles multiple encoding rules:
// 1. Standard: A-B-C-D-1-2-3-4 → A:B:C:D:1:2:3:4
// 2. Condensed: A--C-D → A::C:D
// 3. Leading zeros: 0--B-C-D → ::B:C:D
// 4. Trailing zeros: 1--0 → 1::
func decodeIPv6(encoded string) net.IP {
	// Handle RFC 1123 compliance: replace leading/trailing 0 with empty string
	if strings.HasPrefix(encoded, "0--") {
		encoded = strings.TrimPrefix(encoded, "0")
	}
	if strings.HasSuffix(encoded, "--0") {
		encoded = strings.TrimSuffix(encoded, "0")
	}

	// Replace -- with ::
	ipStr := strings.ReplaceAll(encoded, "--", "::")
	// Replace remaining hyphens with colons
	ipStr = strings.ReplaceAll(ipStr, "-", ":")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	// Ensure it's actually an IPv6 address
	if ip.To4() != nil {
		return nil
	}
	return ip
}
