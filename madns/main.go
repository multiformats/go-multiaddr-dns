package main

import (
	"fmt"
	"os"

	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
)

func main() {
	maddr, err := ma.NewMultiaddr(os.Args[1])
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
