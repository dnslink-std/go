package main

import (
	"encoding/json"
	"fmt"
	"os"

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
	r := &dnslink.Resolver{
		LookupTXT: dnslink.NewUDPLookup([]string{"127.0.0.1:" + fmt.Sprint(options.Udp)}, 0),
	}

	resolved, error := r.ResolveN(domain)
	if error != nil {
		switch e := error.(type) {
		default:
			exitWithError(e.Error())
		case dnslink.RCodeError:
			exitWithError(e.Code)
		}
	}

	result, err := json.MarshalIndent(resolved, "", "  ")
	if err != nil {
		panic(err)
	} else {
		fmt.Print(string(result))
	}
}

func exitWithError(code string) {
	result, err := json.MarshalIndent(map[string]map[string]string{
		"error": {
			"code": code,
		},
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Print(string(result))
	os.Exit(0)
}
