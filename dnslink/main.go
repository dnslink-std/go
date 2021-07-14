package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	dnslink "github.com/dnslink-std/go"
)

type WriteOptions struct {
	domains   []string
	debug     bool
	err       *log.Logger
	out       *log.Logger
	searchKey interface{}
}

type Writer interface {
	write(lookup string, result dnslink.Result)
	end()
}

type WriteJSON struct {
	firstOut bool
	firstErr bool
	options  WriteOptions
}

func NewWriteJSON(options WriteOptions) *WriteJSON {
	write := WriteJSON{
		firstOut: true,
		firstErr: true,
		options:  options,
	}
	if len(options.domains) > 1 {
		options.out.Println("[")
	}
	if options.debug {
		options.err.Println("[")
	}
	return &write
}

func (write *WriteJSON) write(lookup string, result dnslink.Result) {
	out := write.options.out
	err := write.options.err
	prefix := ""
	if write.firstOut {
		write.firstOut = false
	} else {
		prefix = ","
	}

	outLine := map[string]interface{}{
		"links": result.Links,
		"path":  result.Path,
	}

	if len(write.options.domains) > 1 {
		outLine["lookup"] = lookup
	}

	jsonOutline, error := json.Marshal(outLine)
	if error != nil {
		panic(error)
	}
	out.Print(prefix + string(jsonOutline))
	if write.options.debug {
		for _, statement := range result.Log {
			prefix := ""
			if write.firstErr {
				write.firstErr = true
			} else {
				prefix = "\n,"
			}
			errLine := map[string]interface{}{
				"code": statement.Code,
			}
			if statement.Domain != "" {
				errLine["domain"] = statement.Domain
			}
			if statement.Entry != "" {
				errLine["entry"] = statement.Entry
			}
			if statement.Pathname != "" {
				errLine["pathname"] = statement.Pathname
			}
			if statement.Reason != "" {
				errLine["reason"] = statement.Reason
			}
			if len(statement.Search) > 0 {
				errLine["search"] = statement.Search
			}
			if len(write.options.domains) > 1 {
				errLine["lookup"] = lookup
			}
			jsonErrline, error := json.Marshal(errLine)
			if error != nil {
				panic(error)
			}
			err.Print(prefix + string(jsonErrline))
		}
	}
}

func (write *WriteJSON) end() {
	if len(write.options.domains) > 1 {
		write.options.out.Print("]")
	}
	if write.options.debug {
		write.options.err.Print("]")
	}
}

type WriteTXT struct {
	firstOut bool
	firstErr bool
	options  WriteOptions
}

func NewWriteTXT(options WriteOptions) *WriteTXT {
	return &WriteTXT{
		firstOut: true,
		firstErr: true,
		options:  options,
	}
}

func (write *WriteTXT) write(lookup string, result dnslink.Result) {
	out := write.options.out
	err := write.options.err
	prefix := ""
	if len(write.options.domains) > 1 {
		prefix = lookup + ": "
	}
	for key, values := range result.Links {
		for _, entry := range values {
			value := entry.Value
			value += " [ttl=" + fmt.Sprint(entry.Ttl) + "]"
			for _, part := range result.Path {
				value += " [path=" + renderPath(part) + "]"
			}

			if write.options.searchKey != false {
				if write.options.searchKey != key {
					continue
				}
				out.Println(prefix + value)
			} else {
				out.Println(prefix + "/" + key + "/" + value)
			}
		}
	}
	if write.options.debug {
		for _, logEntry := range result.Log {
			optional := ""
			if logEntry.Pathname != "" {
				optional += " pathname=" + logEntry.Pathname
			}
			if len(logEntry.Search) > 0 {
				optional += " search=" + renderSearch(logEntry.Search)
			}
			if logEntry.Entry != "" {
				optional += " entry=" + logEntry.Entry
			}
			if logEntry.Reason != "" {
				optional += " reason=" + logEntry.Reason
			}
			err.Println("[" + logEntry.Code + "] domain=" + logEntry.Domain + optional)
		}
	}
}

func renderPath(path dnslink.PathEntry) string {
	result := ""
	if path.Pathname != "" {
		result += path.Pathname
	}
	if len(path.Search) > 0 {
		result += renderSearch(path.Search)
	}
	return result
}

func renderSearch(search url.Values) string {
	if len(search) == 0 {
		return ""
	}
	result := "?"
	prev := false
	for key, values := range search {
		for _, value := range values {
			if prev {
				result += "&"
			} else {
				prev = true
			}
			result += url.QueryEscape(key) + "=" + url.QueryEscape(value)
		}
	}
	return result
}

func (write *WriteTXT) end() {}

type WriteCSV struct {
	firstOut bool
	firstErr bool
	options  WriteOptions
}

func NewWriteCSV(options WriteOptions) *WriteCSV {
	return &WriteCSV{
		firstOut: true,
		firstErr: true,
		options:  options,
	}
}

func (write *WriteCSV) write(lookup string, result dnslink.Result) {
	out := write.options.out
	err := write.options.err
	if write.firstOut {
		write.firstOut = false
		out.Println("lookup,key,value,ttl,path")
	}
	for key, values := range result.Links {
		for _, value := range values {
			if write.options.searchKey != false && write.options.searchKey != key {
				continue
			}
			out.Println(csv(lookup, key, value.Value, value.Ttl, renderPaths(result.Path)))
		}
	}
	if write.options.debug {
		for _, logEntry := range result.Log {
			if write.firstErr {
				write.firstErr = false
				err.Println("domain,pathname,search,code,entry,reason")
			}
			err.Println(csv(logEntry.Domain, logEntry.Pathname, renderSearch(logEntry.Search), logEntry.Code, logEntry.Entry, logEntry.Reason))
		}
	}
}

func csv(rest ...interface{}) string {
	result := ""
	prefix := ""
	for _, entry := range rest {
		value := ""
		switch v := entry.(type) {
		case int:
		case uint32:
			value = fmt.Sprint(v)
		case bool:
			if v {
				value = "true"
			} else {
				value = "false"
			}
		case string:
			value = `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
		}
		result += prefix + value
		prefix = ","
	}
	return result
}

func renderPaths(paths []dnslink.PathEntry) string {
	result := ""
	prefix := ""
	for _, path := range paths {
		result += prefix + renderPath(path)
		prefix = " → "
	}
	return result
}

func (write *WriteCSV) end() {}

var formats []interface{} = []interface{}{"json", "txt", "csv"}

func main() {
	options, lookups := getOptions(os.Args[1:])
	if options.has("help", "h") {
		showHelp("dnslink")
		return
	}
	if options.has("version", "v") {
		showVersion()
		return
	}
	if len(lookups) == 0 {
		showHelp("dnslink")
		os.Exit(1)
		return
	}
	format := options.firstMatch(formats, "format", "f")
	if format == false {
		format = "txt"
	}
	writeOpts := WriteOptions{
		domains:   lookups,
		searchKey: options.first("key", "k"),
		debug:     options.has("debug") || options.has("d"),
		err:       log.New(os.Stderr, "", 0),
		out:       log.New(os.Stdout, "", 0),
	}
	var output Writer
	if format == "txt" {
		output = NewWriteTXT(writeOpts)
	} else if format == "csv" {
		output = NewWriteCSV(writeOpts)
	} else {
		output = NewWriteJSON(writeOpts)
	}
	resolver := dnslink.Resolver{}
	if options.has("dns") {
		resolver.LookupTXT = dnslink.NewUDPLookup(getServers(options.get("dns")), 0)
	}
	for _, lookup := range lookups {
		var result dnslink.Result
		var error error
		if options.has("nr", "non-recursive") {
			result, error = resolver.Resolve(lookup)
		} else {
			result, error = resolver.ResolveN(lookup)
		}
		if error != nil {
			panic(error)
		}
		output.write(lookup, result)
	}
	output.end()
}

func getServers(raw []interface{}) []string {
	servers := []string{}
	for _, entry := range raw {
		switch string := entry.(type) {
		case string:
			servers = append(servers, string)
		}
	}
	return servers
}

func showHelp(command string) int {
	fmt.Printf(command + ` - resolve dns links in TXT records

USAGE
    ` + command + ` [--help] [--format=json|text|csv] [--key=<key>] [--debug] \\
        [--dns=server] [--non-recursive] \\
        <hostname> [...<hostname>]

EXAMPLE
    # Recursively receive the dnslink entries for the dnslink.io domain.
    > ` + command + ` dnslink.io
    /ipfs/QmTgQDr3xNgKBVDVJtyGhopHoxW4EVgpkfbwE4qckxGdyo

    # Receive only the ipfs entry as text for dnslink.io
    > ` + command + ` -k=ipfs dnslink.io
    QmTgQDr3xNgKBVDVJtyGhopHoxW4EVgpkfbwE4qckxGdyo

    # Receive all dnslink entries for multiple domains as csv
    > ` + command + ` -f=csv dnslink.io ipfs.io
    lookup,key,value,path
    "dnslink.io","ipfs","QmTgQDr3xNgKBVDVJtyGhopHoxW4EVgpkfbwE4qckxGdyo",
    "ipfs.io","ipns","website.ipfs.io",

    # Receive ipfs entries for multiple domains as json
    > ` + command + ` -f=json -k=ipfs dnslink.io website.ipfs.io
    [
    {"lookup":"website.ipfs.io","links":{"ipfs":"bafybeiagozluzfopjadeigrjlsmktseozde2xc5prvighob7452imnk76a"},"path":[]}
    ,{"lookup":"dnslink.io","links":{"ipfs":"QmTgQDr3xNgKBVDVJtyGhopHoxW4EVgpkfbwE4qckxGdyo"},"path":[]}
    ]

    # Receive both the result and log and write the output to files
    > ` + command + ` -f=csv -d dnslink.io \\
        >dnslink-io.csv \\
        2>dnslink-io.log.csv

OPTIONS
    --help, -h             Show this help.
    --version, -v          Show the version of this command.
    --format, -f           Output format json, text or csv (default=json)
    --dns=<server>         Specify a dns server to use. If you don't specify a
                           server it will use the system dns service. As server you
                           can specify a domain with port: 1.1.1.1:53
    --debug, -d            Render log output to stderr in the specified format.
    --key, -k              Only render one particular dnslink key.
    --non-recursive, -nr   Prevent Lookup of recursive dnslink entries.

    Read more about it here: https://github.com/dnslink-std/go

dnslink-go@` + dnslink.Version)
	return 0
}

func showVersion() int {
	fmt.Println(dnslink.Version)
	return 0
}

type Options struct {
	All map[string][]interface{} `json:"all"`
}

func (o *Options) has(keys ...string) bool {
	if o.All == nil {
		return false
	}
	for _, key := range keys {
		_, hasOption := o.All[key]
		if hasOption {
			return true
		}
	}
	return false
}

func (o *Options) get(keys ...string) []interface{} {
	if o.All == nil {
		return []interface{}{}
	}
	result := []interface{}{}
	for _, key := range keys {
		values, hasOption := o.All[key]
		if hasOption {
			result = append(result, values...)
		}
	}
	return result
}

func (o *Options) first(keys ...string) interface{} {
	values := o.get(keys...)
	if len(values) == 0 {
		return false
	}
	return values[0]
}

func (o *Options) firstMatch(matches []interface{}, keys ...string) interface{} {
	values := o.get(keys...)
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		for _, match := range matches {
			if value == match {
				return value
			}
		}
	}
	return false
}

func (o *Options) add(key string, value interface{}) {
	if o.All == nil {
		o.All = map[string][]interface{}{}
	}
	values, hasOption := o.All[key]
	if !hasOption {
		o.All[key] = []interface{}{value}
	} else {
		o.All[key] = append(values, value)
	}
}

func getOptions(args []string) (Options, []string) {
	options := Options{}
	rest := []string{}[:]
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			arg = arg[2:]
		} else if strings.HasPrefix(arg, "-") {
			arg = arg[1:]
		} else {
			rest = append(rest, arg)
			continue
		}
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) > 1 {
			options.add(parts[0], parts[1])
		} else {
			options.add(parts[0], true)
		}
	}
	return options, rest
}
