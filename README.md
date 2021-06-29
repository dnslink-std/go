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

// If you want to follow dnslink redirects, you need to use ResolveN
result, error = dnslink.ResolveN("dnslink.dev")

if error != nil {
  panic(error) // An error may occur if the domain can not be found.
}

// `links` property is a map[string]string containing given links for the different keys
result.Links["ipfs"] == "QmTg....yomU"

// The `log` is always an Array and contains a list of log entries
// that were should help to trace back how the linked data was resolved.
result.Log

// The `path` is always an []dnslink.PathEntry array that may contain a list of paths that
// each link may uses to deep-resolve values. The list is sorted from
// first to last.
result.Path
```

You can configure the DNS resolution

```go
import {
  "net"
  "context"
  "time"
}

const dnsServerAddress = "1.1.1.1:53"
dns := &net.Resolver{
  PreferGo: true,
  Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
    d := net.Dialer{
      Timeout: time.Millisecond * time.Duration(10000),
    }
    return d.DialContext(ctx, network, dnsServerAddress)
  },
}
resolver := &dnslink.Resolver{
  LookupTXT: func(name string) (txt []string, err error) {
    return dns.LookupTXT(context.Background(), name)
  },
}

// The resolver will now use googles 1.1.1.1 dns server.
resolver.ResolveN("dnslink.dev")
```

## Possible log statements

The statements contained in the `log` are all `dnslink.LogStatements`. They may be helpful to figure out why dnslink
is not behaving like you expect. Every statement contains the `.code` property that holds the `.code`
property to understand what happened.
Depending on the warnings code the errors may have additional `.entry` property that holds
the problematic TXT entry. A `.reason` property may contain an additional reason for that error to occur.
If redirects are employed or 
Note that the order of the `RESOLVE` and `REDIRECT` entries are relevant, as they are point to the `.domain`
at which previous errors occured. The entries between `RESOLVE` and `REDIRECT` statements however may
be shuffled. These and other codes may additionally contain a `.pathname` and `.search` property,
each containing their contribution to the path.


| `.code`                  | Meaning                                                              | Additional properties               |
|--------------------------|----------------------------------------------------------------------|-------------------------------------|
| RESOLVE                  | This domain name will be used for resolving.                         | `.domain`, (`.pathname`, `.search`) |
| REDIRECT                 | Redirecting away from the specified domain name.                     | `.domain`, (`.pathname`, `.search`) |
| CONFLICT_ENTRY           | Multiple entries for a key were found and an entry has been ignored. | `.entry`                            |
| INVALID_ENTRY            | A TXT entry with `dnslink=` prefix has formatting errors.            | `.entry`, `.reason`                 |
| RECURSIVE_DNSLINK_PREFIX | The hostname requested contains multiple `_dnslink` prefixes.        |                                     |
| UNUSED_ENTRY             | An entry is unused because a redirect overrides it.                  | `.entry`                            |
| ENDLESS_REDIRECT         | Endless DNSLink redirects detected.                                  | `.domain`, (`.pathname`, `.search`) |
| INVALID_REDIRECT         | A given redirect is of invalid format.                               | `.domain`, (`.pathname`, `.search`) |
| TOO_MANY_REDIRECTS       | Too many redirects happend. (max=32 per dnslink spec)                | `.domain`, (`.pathname`, `.search`) |

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
