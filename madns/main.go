package main

import (
	"fmt"
	"os"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
)

func main() {
	query := os.Args[1]
	if !strings.HasPrefix(query, "/") {
		query = "/dnsaddr/" + query
		fmt.Fprintf(os.Stderr, "madns: changing query to %s\n", query)
	}

	maddr, err := ma.NewMultiaddr(query)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	rmaddrs, err := madns.Resolve(maddr)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	for _, r := range rmaddrs {
		fmt.Println(r.String())
	}
}
