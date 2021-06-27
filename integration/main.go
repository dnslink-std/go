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

	cleanLog := make([]map[string]interface{}, len(resolved.Log))
	// logLen := len(cleanLog)
	for index, entry := range resolved.Log {
		cleanEntry := make(map[string]interface{})
		cleanEntry["code"] = entry.Code
		if entry.Domain != "" {
			cleanEntry["domain"] = entry.Domain
		}
		if entry.Entry != "" {
			cleanEntry["entry"] = entry.Entry
		}
		if entry.Pathname != "" {
			cleanEntry["pathname"] = entry.Pathname
		}
		if entry.Reason != "" {
			cleanEntry["reason"] = entry.Reason
		}
		if entry.Search != nil && len(entry.Search) != 0 {
			cleanEntry["search"] = entry.Search
		}
		cleanLog[index] = cleanEntry
	}
	result, err := json.Marshal(struct {
		Links map[string]string        `json:"links"`
		Path  []dnslink.PathEntry      `json:"path"`
		Log   []map[string]interface{} `json:"log"`
	}{
		Links: resolved.Links,
		Path:  resolved.Path,
		Log:   cleanLog,
	})
	if err != nil {
		panic(err)
	} else {
		fmt.Print(string(result))
	}
}
