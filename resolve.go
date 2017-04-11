package madns

import (
	"context"
	"fmt"
	"net"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

var ResolvableProtocols = []ma.Protocol{DnsaddrProtocol, Dns4Protocol, Dns6Protocol}

type resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupTXT(context.Context, string) ([]string, error)
}

type Resolver struct {
	Resolver resolver
}

var DefaultResolver = &Resolver{Resolver: net.DefaultResolver}

func Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	return DefaultResolver.Resolve(ctx, maddr)
}

func (r *Resolver) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	resolvable, proto := isResolvable(maddr)
	if !resolvable {
		return []ma.Multiaddr{maddr}, nil
	}

	if proto.Code == Dns4Protocol.Code {
		return r.resolveDns4(ctx, maddr)
	}
	if proto.Code == Dns6Protocol.Code {
		return r.resolveDns6(ctx, maddr)
	}
	if proto.Code == DnsaddrProtocol.Code {
		return r.resolveDnsaddr(ctx, maddr)
	}

	panic("unreachable")
}

func (r *Resolver) resolveDns4(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	value, err := maddr.ValueForProtocol(Dns4Protocol.Code)
	if err != nil {
		return nil, fmt.Errorf("error resolving %s: %s", maddr.String(), err)
	}

	encap := ma.Split(maddr)[1:]

	result := []ma.Multiaddr{}
	records, err := r.Resolver.LookupIPAddr(ctx, value)
	if err != nil {
		return result, err
	}

	for _, r := range records {
		ip4 := r.IP.To4()
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

func (r *Resolver) resolveDns6(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	value, err := maddr.ValueForProtocol(Dns6Protocol.Code)
	if err != nil {
		return nil, fmt.Errorf("error resolving %s: %s", maddr.String(), err)
	}

	encap := ma.Split(maddr)[1:]

	result := []ma.Multiaddr{}
	records, err := r.Resolver.LookupIPAddr(ctx, value)
	if err != nil {
		return result, err
	}

	for _, r := range records {
		if r.IP.To4() != nil {
			continue
		}
		ip6maddr, err := ma.NewMultiaddr("/ip6/" + r.IP.To16().String())
		if err != nil {
			return result, err
		}
		parts := append([]ma.Multiaddr{ip6maddr}, encap...)
		result = append(result, ma.Join(parts...))
	}
	return result, nil
}

func (r *Resolver) resolveDnsaddr(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	value, err := maddr.ValueForProtocol(DnsaddrProtocol.Code)
	if err != nil {
		return nil, fmt.Errorf("error resolving %s: %s", maddr.String(), err)
	}

	trailer := ma.Split(maddr)[1:]

	result := []ma.Multiaddr{}
	records, err := r.Resolver.LookupTXT(ctx, "_dnsaddr."+value)
	if err != nil {
		return result, err
	}

	for _, r := range records {
		rv := strings.Split(r, "dnsaddr=")
		if len(rv) != 2 {
			continue
		}

		rmaddr, err := ma.NewMultiaddr(rv[1])
		if err != nil {
			return result, err
		}

		if matchDnsaddr(rmaddr, trailer) {
			result = append(result, rmaddr)
		}
	}
	return result, nil
}

func isResolvable(maddr ma.Multiaddr) (bool, *ma.Protocol) {
	protos := maddr.Protocols()
	if len(protos) == 0 {
		return false, nil
	}

	for _, p := range ResolvableProtocols {
		if protos[0].Code == p.Code {
			return true, &p
		}
	}

	return false, nil
}

// XXX probably insecure
func matchDnsaddr(maddr ma.Multiaddr, trailer []ma.Multiaddr) bool {
	parts := ma.Split(maddr)
	if ma.Join(parts[len(parts)-len(trailer):]...).Equal(ma.Join(trailer...)) {
		return true
	}
	return false
}
