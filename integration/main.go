package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	dnslink "github.com/dnslink-std/go"
)

type Options struct {
	Udp   int             `json:"udp"`
	Tcp   int             `json:"tcp"`
	Doh   int             `json:"doh"`
	Flags map[string]bool `json:"flags"`
}

func main() {
	domain := os.Args[1]
	options := Options{}
	json.Unmarshal([]byte(os.Args[2]), &options)
	dns := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, "127.0.0.1:"+fmt.Sprint(options.Udp))
		},
	}
	r := &dnslink.Resolver{
		LookupTXT: func(name string) (txt []string, err error) {
			return dns.LookupTXT(context.Background(), name)
		},
	}

	resolved, error := r.ResolveN(domain)
	if error != nil {
		panic(error)
	}

	result, err := json.Marshal(resolved)
	if err != nil {
		panic(err)
	} else {
		fmt.Print(string(result))
	}
}
