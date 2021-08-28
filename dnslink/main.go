package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	dnslink "github.com/dnslink-std/go"
)

type WriteOptions struct {
	domains  []string
	debug    bool
	err      *log.Logger
	out      *log.Logger
	firstNS  interface{}
	searchNS interface{}
	ttl      bool
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

	outLine := map[string]interface{}{}
	if write.options.ttl {
		outLine["links"] = result.Links
		outLine["txtEntries"] = result.TxtEntries
	} else {
		noTtl := result.NoTtl()
		outLine["links"] = noTtl.Links
		outLine["txtEntries"] = noTtl.TxtEntries
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
			if statement.Entry != "" {
				errLine["entry"] = statement.Entry
			}
			if statement.Reason != "" {
				errLine["reason"] = statement.Reason
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
	for ns, values := range result.Links {
		if write.options.searchNS != false && write.options.searchNS != ns {
			continue
		}
		for _, entry := range values {
			identifier := entry.Identifier
			if write.options.ttl {
				identifier += " [ttl=" + fmt.Sprint(entry.Ttl) + "]"
			}

			if write.options.searchNS != false {
				if write.options.searchNS != ns {
					continue
				}
				out.Println(prefix + identifier)
			} else {
				out.Println(prefix + "/" + ns + "/" + identifier)
			}
			if write.options.firstNS != false {
				break
			}
		}
	}
	if write.options.debug {
		for _, logEntry := range result.Log {
			optional := ""
			if logEntry.Entry != "" {
				optional += " entry=" + logEntry.Entry
			}
			if logEntry.Reason != "" {
				optional += " reason=" + logEntry.Reason
			}
			err.Println("[" + logEntry.Code + "]" + optional)
		}
	}
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
		line := "lookup,namespace,identifier"
		if write.options.ttl {
			line += ",ttl"
		}
		out.Println(line)
	}
	for ns, values := range result.Links {
		if write.options.searchNS != false && write.options.searchNS != ns {
			continue
		}
		for _, value := range values {
			var line string
			if write.options.ttl {
				line = csv(lookup, ns, value.Identifier, value.Ttl)
			} else {
				line = csv(lookup, ns, value.Identifier)
			}
			out.Println(line)
			if write.options.firstNS != false {
				break
			}
		}
	}
	if write.options.debug {
		for _, logEntry := range result.Log {
			if write.firstErr {
				write.firstErr = false
				err.Println("code,entry,reason")
			}
			err.Println(csv(logEntry.Code, logEntry.Entry, logEntry.Reason))
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
		domains:  lookups,
		firstNS:  options.first("first"),
		searchNS: options.first("first", "ns", "n"),
		debug:    options.has("debug") || options.has("d"),
		err:      log.New(os.Stderr, "", 0),
		out:      log.New(os.Stdout, "", 0),
		ttl:      options.has("ttl"),
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
		result, err := resolver.Resolve(lookup)
		if err != nil {
			panic(err)
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
    ` + command + ` [--help] [--format=json|text|csv] [--ns=<ns>] \
        [--first=<ns>] [--dns=server] [--debug] \
        <hostname> [...<hostname>]

EXAMPLE
    # Receive the dnslink entries for the dnslink.io domain.
    > ` + command + ` dnslink.dev
    /ipfs/QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF

    # Receive only namespace "ipfs" entries as text for dnslink.io.
    > ` + command + ` --ns=ipfs dnslink.dev
    QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF

    # Receive only the first ipfs entry for the "ipfs" namespace.
    > ` + command + ` --first=ipfs dnslink.dev
    QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF

    # Getting information about the --ttl as received from the server.
    > ` + command + ` --ttl dnslink.dev
    /ipfs/QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF  [ttl=53]

    # Receive the dnslink entries using the system DNS.
    > ` + command + ` --dns dnslink.dev
    /ipfs/QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF

    # Receive all dnslink entries for multiple domains as csv.
    > ` + command + ` --format=csv dnslink.dev ipfs.io
    lookup,namespace,identifier
    "ipfs.io","ipns","website.ipfs.io"
    "dnslink.dev","ipfs","QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF"

    # Receive ipfs entries for multiple domains as json.
    > ` + command + ` --format=json dnslink.dev ipfs.io
    [
    {"lookup":"ipfs.io","txtEntries":["/ipns/website.ipfs.io"],"links":{"ipns":["website.ipfs.io"]}}
    ,{"lookup":"dnslink.dev","txtEntries":["/ipfs/QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF"],"links":{"ipfs":["QmXNosdfz3WQUHncsYBTw7diwYzCibVhrJmEhNNaMPQBQF"]}}
    ]

    # Receive both the result and log as csv and redirect each to files.
    > ` + command + ` --format=csv --debug dnslink.io \
        >dnslink-io.csv \
        2>dnslink-io.log.csv

OPTIONS
    --help, -h             Show this help.
    --version, -v          Show the version of this command.
    --format, -f           Output format json, text or csv (default=text)
    --ttl                  Include ttl in output (any format)
    --dns=<server>         Specify a dns server to use. If you don't specify a
                           server it will use the system dns service. As server you
                           can specify a domain with port: 1.1.1.1:53
    --debug, -d            Render log output to stderr in the specified format.
    --ns, -n               Only render one particular DNSLink namespace.
    --first                Only render the first of the defined DNSLink namespace.

Read more about DNSLink at https://dnslink.dev.

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
