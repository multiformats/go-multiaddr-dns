package madns

import (
	"fmt"
	"net"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

var ResolvableProtocols = []ma.Protocol{DnsaddrProtocol, Dns4Protocol, Dns6Protocol}

func Resolve(maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	protos := maddr.Protocols()
	if len(protos) == 0 {
		return []ma.Multiaddr{maddr}, nil
	}

	resolvable := false
	for _, p := range ResolvableProtocols {
		if protos[0].Code == p.Code {
			resolvable = true
		}
	}
	if !resolvable {
		return []ma.Multiaddr{maddr}, nil
	}

	if protos[0].Code == Dns4Protocol.Code {
		return resolveDns4(maddr)
	}
	if protos[0].Code == Dns6Protocol.Code {
		return resolveDns6(maddr)
	}
	if protos[0].Code == DnsaddrProtocol.Code {
		return resolveDnsaddr(maddr)
	}

	panic("unreachable")
}

func resolveDns4(maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	value, err := maddr.ValueForProtocol(Dns4Protocol.Code)
	if err != nil {
		return nil, fmt.Errorf("error resolving %s: %s", maddr.String(), err)
	}

	encap := ma.Split(maddr)[1:]

	records, err := net.LookupIP(value)
	result := []ma.Multiaddr{}

	for _, r := range records {
		ip4 := r.To4()
		if ip4 == nil {
			continue
		}
		ip4maddr, err := ma.NewMultiaddr("/ip4/" + ip4.String())
		if err != nil {
			return result, err
		}
		parts := append([]ma.Multiaddr{ip4maddr}, encap...)
		result = append(result, ma.Join(parts...))
	}
	return result, nil
}

func resolveDns6(maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	value, err := maddr.ValueForProtocol(Dns6Protocol.Code)
	if err != nil {
		return nil, fmt.Errorf("error resolving %s: %s", maddr.String(), err)
	}

	encap := ma.Split(maddr)[1:]

	records, err := net.LookupIP(value)
	result := []ma.Multiaddr{}

	for _, r := range records {
		ip6 := r.To16()
		if r.To4() != nil {
			continue
		}
		ip6maddr, err := ma.NewMultiaddr("/ip6/" + ip6.String())
		if err != nil {
			return result, err
		}
		parts := append([]ma.Multiaddr{ip6maddr}, encap...)
		result = append(result, ma.Join(parts...))
	}
	return result, nil
}

func resolveDnsaddr(maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	value, err := maddr.ValueForProtocol(DnsaddrProtocol.Code)
	if err != nil {
		return nil, fmt.Errorf("error resolving %s: %s", maddr.String(), err)
	}

	trailer := ma.Split(maddr)[1:]

	records, err := net.LookupTXT("_dnsaddr." + value)
	result := []ma.Multiaddr{}

	for _, r := range records {
		rv := strings.Split(r, "dnsaddr=")
		if len(rv) != 2 {
			continue
		}

		rmaddr, err := ma.NewMultiaddr(rv[1])
		if err != nil {
			return result, err
		}

		parts := ma.Split(rmaddr)
		if ma.Join(parts[len(parts)-len(trailer):]...).Equal(ma.Join(trailer...)) {
			result = append(result, rmaddr)
		}
	}
	return result, nil
}
