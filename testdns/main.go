package main

import (
	"log"

	dns "github.com/miekg/dns"
)

func main() {
	handler := new(dnsHandler)
	handler.addrs = map[string][]string{
		"_dnsaddr.libp2p.io.": []string{
			// XXX both "go" and "cgo" dns clients are shitting themselves with too large responses
			"dnsaddr=/ip4/104.236.151.122/tcp/4001/ipfs/QmSoLju6m7xTh3DuokvT3886QRYqxAzb1kShaanJgW36yx",
			"dnsaddr=/ip6/2604:a880:1:20::1d9:6001/tcp/4001/ipfs/QmSoLju6m7xTh3DuokvT3886QRYqxAzb1kShaanJgW36yx",
			"dnsaddr=/ip6/fc3d:9a4e:3c96:2fd2:1afa:18fe:8dd2:b602/tcp/4001/ipfs/QmSoLju6m7xTh3DuokvT3886QRYqxAzb1kShaanJgW36yx",
			"dnsaddr=/dns4/jupiter.i.ipfs.io/tcp/4001/ipfs/QmSoLju6m7xTh3DuokvT3886QRYqxAzb1kShaanJgW36yx",
			"dnsaddr=/dns6/jupiter.i.ipfs.io/tcp/4001/ipfs/QmSoLju6m7xTh3DuokvT3886QRYqxAzb1kShaanJgW36yx",
		},
	}
	err := dns.ListenAndServe(":53", "udp", handler)
	if err != nil {
		log.Fatal(err)
	}
}

type dnsHandler struct {
	addrs map[string][]string
}

func (h dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 0 {
		name := r.Question[0].Name
		txts, ok := h.addrs[name]
		if !ok {
			m := new(dns.Msg)
			m.SetReply(r)
			w.WriteMsg(m)
			return
		}

		for _, txt := range txts {
			rr := new(dns.TXT)
			rr.Hdr = dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    10,
			}
			rr.Txt = []string{txt}

			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = []dns.RR{rr}
			w.WriteMsg(m)
		}
	}

	log.Printf("req: %+v\n", r.Question[0].Name)
}
