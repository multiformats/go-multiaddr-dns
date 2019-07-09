package madns

import (
	"context"
	"net"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

var ResolvableProtocols = []ma.Protocol{DnsaddrProtocol, Dns4Protocol, Dns6Protocol}
var DefaultResolver = &Resolver{Backend: net.DefaultResolver}

const dnsaddrTXTPrefix = "dnsaddr="

type backend interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupTXT(context.Context, string) ([]string, error)
}

type Resolver struct {
	Backend backend
}

type MockBackend struct {
	IP  map[string][]net.IPAddr
	TXT map[string][]string
}

func (r *MockBackend) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	results, ok := r.IP[name]
	if ok {
		return results, nil
	} else {
		return []net.IPAddr{}, nil
	}
}

func (r *MockBackend) LookupTXT(ctx context.Context, name string) ([]string, error) {
	results, ok := r.TXT[name]
	if ok {
		return results, nil
	} else {
		return []string{}, nil
	}
}

func Matches(maddr ma.Multiaddr) (matches bool) {
	ma.ForEach(maddr, func(c ma.Component) bool {
		switch c.Protocol().Code {
		case Dns4Protocol.Code, Dns6Protocol.Code, DnsaddrProtocol.Code:
			matches = true
		}
		return !matches
	})
	return matches
}

func Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	return DefaultResolver.Resolve(ctx, maddr)
}

func (r *Resolver) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	var results []ma.Multiaddr
	for i := 0; maddr != nil; i++ {
		var keep ma.Multiaddr
		keep, maddr = ma.SplitFunc(maddr, func(c ma.Component) bool {
			switch c.Protocol().Code {
			case Dns4Protocol.Code, Dns6Protocol.Code, DnsaddrProtocol.Code:
				return true
			default:
				return false
			}
		})

		// Append the part we're keeping.
		if keep != nil {
			if results == nil {
				results = append(results, keep)
			} else {
				for i, r := range results {
					results[i] = r.Encapsulate(keep)
				}
			}
		}

		// Check to see if we're done.
		if maddr == nil {
			break
		}

		var resolve *ma.Component
		resolve, maddr = ma.SplitFirst(maddr)

		proto := resolve.Protocol()
		value := resolve.Value()

		var resolved []ma.Multiaddr
		switch proto.Code {
		case Dns4Protocol.Code, Dns6Protocol.Code:
			v4 := proto.Code == Dns4Protocol.Code

			// XXX: Unfortunately, go does a pretty terrible job of
			// differentiating between IPv6 and IPv4. A v4-in-v6
			// AAAA record will _look_ like an A record to us and
			// there's nothing we can do about that.
			records, err := r.Backend.LookupIPAddr(ctx, value)
			if err != nil {
				return nil, err
			}

			for _, r := range records {
				var (
					rmaddr ma.Multiaddr
					err    error
				)
				ip4 := r.IP.To4()
				if v4 {
					if ip4 == nil {
						continue
					}
					rmaddr, err = ma.NewMultiaddr("/ip4/" + ip4.String())
				} else {
					if ip4 != nil {
						continue
					}
					rmaddr, err = ma.NewMultiaddr("/ip6/" + r.IP.String())
				}
				if err != nil {
					return nil, err
				}
				resolved = append(resolved, rmaddr)
			}
		case DnsaddrProtocol.Code:
			records, err := r.Backend.LookupTXT(ctx, "_dnsaddr."+value)
			if err != nil {
				return nil, err
			}

			length := 0
			if maddr != nil {
				length = addrLen(maddr)
			}
			for _, r := range records {
				if !strings.HasPrefix(r, dnsaddrTXTPrefix) {
					continue
				}
				rmaddr, err := ma.NewMultiaddr(r[len(dnsaddrTXTPrefix):])
				if err != nil {
					// discard multiaddrs we don't understand.
					// XXX: Is this right?
					continue
				}

				if maddr != nil {
					rmlen := addrLen(rmaddr)
					if rmlen < length {
						// not long enough.
						continue
					}

					// Matches everything after the /dnsaddr/... with the end of the
					// dnsaddr record:
					//
					// v----------rmlen-----------------v
					// /ip4/1.2.3.4/tcp/1234/p2p/QmFoobar
					//                      /p2p/QmFoobar
					// ^--(rmlen - length)--^---length--^
					if !maddr.Equal(offset(rmaddr, rmlen-length)) {
						continue
					}
				}

				resolved = append(resolved, rmaddr)
			}

			// consumes the rest of the multiaddr as part of the "match" process.
			maddr = nil
		default:
			panic("unreachable")
		}

		if len(resolved) == 0 {
			return nil, nil
		} else if len(results) == 0 {
			results = resolved
		} else {
			results = cross(results, resolved)
		}
	}
	return results, nil
}

func addrLen(maddr ma.Multiaddr) int {
	length := 0
	ma.ForEach(maddr, func(_ ma.Component) bool {
		length++
		return true
	})
	return length
}

func offset(maddr ma.Multiaddr, offset int) ma.Multiaddr {
	_, after := ma.SplitFunc(maddr, func(c ma.Component) bool {
		if offset == 0 {
			return true
		}
		offset--
		return false
	})
	return after
}

func cross(a, b []ma.Multiaddr) []ma.Multiaddr {
	res := make([]ma.Multiaddr, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			res = append(res, x.Encapsulate(y))
		}
	}
	return res
}
