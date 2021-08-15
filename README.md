# dnslink-std/go

The reference implementation for DNSLink in golang.

## Usage

You can use dnslink both as code and as an CLI tool.

## Golang API

Getting started with the dnslink in a jiffy:

```go
import {
	dnslink "github.com/dnslink-std/go"
}

result, error := dnslink.Resolve("dnslink.dev")

if error != nil {
  switch e := error.(type) {
  default:
    // A variety other errors may be returned. Possible causes include, but are not limited to:
    // - Invalid input
    // - Timeouts / aborts
    // - Networking errors
    // - Incompatible dns packets provided by server
    panic(e)
  case dnslink.RCodeError:
    err.RCode // Error code number following - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    err.RCode.Name() // Error code name following (same list)
    err.Code // "RCODE_%s", err.RCode
    err.Domain // Domain lookup that resulted in the error
    if e.RCode == 3 {
      // NXDomain = Domain not found; most relevant error
    }
  }
}

// `links` property is a map[string][]string containing given links for the different keys, sorted.
result.Links["ipfs"][0] == "QmTg....yomU"

// The `log` is always an Array and contains a list of log entries
// that were should help to trace back how the linked data was resolved.
result.Log
```

You can configure the DNS resolution

```go
import {
  "net"
  "context"
  "time"
}

resolver := &dnslink.Resolver{
  LookupTXT: dnslink.NewUDPLookup("1.1.1.1:53"),
}

// The resolver will now use googles 1.1.1.1 dns server.
resolver.Resolve("dnslink.dev")
```

## Possible log statements

The statements contained in the `log` are all `dnslink.LogStatements`. They may be helpful to figure out why dnslink
is not behaving like you expect. Every statement contains the `.code` property that holds the `.code`
property to understand what happened.
Depending on the warnings code the errors may have additional `.entry` property that holds the problematic TXT entry.
A `.reason` property may contain an additional reason for that error to occur.

| `.code`                  | Meaning                                                                       | Additional properties |
|--------------------------|-------------------------------------------------------------------------------|-----------------------|
| FALLBACK                 | No `_dnslink.` prefixed domain was found. Falling back to the regular domain. |                       |
| INVALID_ENTRY            | A TXT entry with `dnslink=` prefix has formatting errors.                     | `.entry`, `.reason`   |

## Command Line

To get the [command line tool](./dnslink) you can either install it using `go get`

```sh
go get -u github.com/dnslink-std/go/dnslink
```

Or download a binary asset from the github [release page](https://github.com/dnslink-std/go/releases/latest).

You can get detailed help for the app by passing a `--help` option at the end:

```sh
dnslink --help
```

## License

Published under dual-license: [MIT OR Apache-2.0](./LICENSE)
