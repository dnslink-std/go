package dnslink

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	dns "github.com/miekg/dns"
)

type Search map[string][]string

func (search Search) String() string {
	if len(search) == 0 {
		return ""
	}
	result := "?"
	prev := false
	keys := []string{}
	for key := range search {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := search[key]
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

type PathEntry struct {
	Pathname string
	Search   Search
}

func (p *PathEntry) String() string {
	return p.Pathname + p.Search.String()
}

func (p *PathEntry) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{}
	if p.Pathname != "" {
		out["pathname"] = p.Pathname
	}
	if len(p.Search) > 0 {
		out["search"] = p.Search
	}
	return json.Marshal(out)
}

type PathEntries []PathEntry

func (paths PathEntries) Reduce(input string) (PathEntry, error) {
	urlParts, error := url.Parse(input)
	if error != nil {
		return PathEntry{}, error
	}
	basePath := urlParts.Host + urlParts.Path
	search := searchFromQuery(urlParts.RawQuery)
	pathParts := strings.Split(basePath, "/")[:]
	for _, path := range paths {
		pathname := path.Pathname
		if pathname != "" {
			pathname = strings.TrimPrefix(pathname, "/")
			if strings.HasPrefix(pathname, "/") {
				pathname = pathname[1:]
				pathParts = []string{}
			}
			pathParts = append(pathParts, strings.Split(pathname, "/")...)
		}
		if path.Search != nil {
			search = combineSearch(path.Search, search)
		}
	}
	return PathEntry{
		Pathname: reducePath(pathParts),
		Search:   search,
	}, nil
}

type LogStatement struct {
	Code     string
	Domain   string
	Entry    string
	Reason   string
	Pathname string
	Search   Search
}

func (l *LogStatement) Error() string {
	return l.Code
}

func (stmt *LogStatement) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{
		"code": stmt.Code,
	}
	if stmt.Domain != "" {
		out["domain"] = stmt.Domain
	}
	if stmt.Entry != "" {
		out["entry"] = stmt.Entry
	}
	if stmt.Reason != "" {
		out["reason"] = stmt.Reason
	}
	if stmt.Pathname != "" {
		out["pathname"] = stmt.Pathname
	}
	if len(stmt.Search) > 0 {
		out["search"] = stmt.Search
	}
	return json.Marshal(out)
}

type URLParts struct {
	Domain   string
	Pathname string
	Search   map[string][]string
}

func (url *URLParts) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{
		"domain": url.Domain,
	}
	if url.Pathname != "" {
		out["pathname"] = url.Pathname
	}
	if len(url.Search) > 0 {
		out["search"] = url.Search
	}
	return json.Marshal(out)
}

type Result struct {
	Links map[string][]LookupEntry `json:"links"`
	Path  PathEntries              `json:"path"`
	Log   []LogStatement           `json:"log"`
}

type Resolver struct {
	LookupTXT LookupTXTFunc
}

func (r *Resolver) Resolve(domain string) (Result, error) {
	return resolve(r, domain, false)
}

func (r *Resolver) ResolveN(domain string) (Result, error) {
	return resolve(r, domain, true)
}

type LookupEntry struct {
	Value string `json:"value"`
	Ttl   uint32 `json:"ttl"`
}
type LookupEntries []LookupEntry

func (l LookupEntries) Len() int      { return len(l) }
func (l LookupEntries) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

type ByValue struct{ LookupEntries }

func (s ByValue) Less(i, j int) bool { return s.LookupEntries[i].Value < s.LookupEntries[j].Value }

type LookupTXTFunc func(name string) (txt []LookupEntry, err error)

var utf8Replace = regexp.MustCompile(`\\\d{3}`)

func utf8ReplaceFunc(input []byte) (result []byte) {
	result = make([]byte, 1)
	num, _ := strconv.ParseUint(string(input[1:]), 10, 9)
	result[0] = byte(num)
	return result
}

func utf8Value(input []string) string {
	str := strings.Join(input, "")
	return string(utf8Replace.ReplaceAllFunc([]byte(str), utf8ReplaceFunc))
}

type RCode int

const (
	NoError RCode = iota
	Success
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
	YXDomain
	YXRRSet
	NXRRSet
	NotAuth
	NotZone
	DSOTYPENI
	_
	_
	_
	_
	BADVERS_BADSIG
	BADKEY
	BADTIME
	BADMODE
	BADNAME
	BADALG
	BADTRUNC
	BADCOOKIE
)

var rcodeNames = []string{"Success", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused", "YXDomain", "YXRRSet", "NXRRSet", "NotAuth", "NotZone", "DSOTYPENI", "", "", "", "", "BADVERS_BADSIG", "BADKEY", "BADTIME", "BADMODE", "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE"}
var rcodeDetails = []string{
	"",
	"The name server was unable to interpret the query.",
	"The name server was unable to process this query due to a problem with the name server.",
	"Non-Existent Domain.",
	"The name server does not support the requested kind of query.",
	"The name server refuses to perform the specified operation for policy reasons.",
	"Name Exists when it should not.",
	"RR Set Exists when it should not.",
	"RR Set that should exist does not.",
	"Server Not Authoritative for zone  / Not Authorized.",
	"Name not contained in zone.",
	"DSO-TYPE Not Implemented.",
	"", "", "", "",
	"Bad OPT Version. / TSIG Signature Failure.",
	"Key not recognized.",
	"Signature out of time window",
	"Bad TKEY Mode.",
	"Duplicate key name.",
	"Algorithm not supported.",
	"Bad Truncation.",
	"Bad/missing Server Cookie.",
}

func (code RCode) Name() string {
	if int(code) > len(rcodeNames) {
		return ""
	}
	return rcodeNames[code]
}
func (code RCode) Detail() string {
	if int(code) > len(rcodeDetails) || rcodeDetails[code] == "" {
		return "Undefined Error."
	}
	return rcodeDetails[code]
}

type RCodeError struct {
	RCode  RCode  `json:"rcode"`
	Code   string `json:"code"`
	Name   string `json:"error"`
	Domain string `json:"domain"`
}

func NewRCodeError(rcode int, domain string) RCodeError {
	code := RCode(rcode)
	return RCodeError{
		RCode:  code,
		Name:   code.Name(),
		Code:   fmt.Sprintf("RCODE_%d", rcode),
		Domain: domain,
	}
}

func (e RCodeError) Error() string {
	name := e.RCode.Name()
	if name == "" {
		name = ""
	} else {
		name = fmt.Sprintf("error=%s ,", name)
	}
	return fmt.Sprintf("%s (rcode=%d, %sdomain=%s)", e.RCode.Detail(), int(e.RCode), name, e.Domain)
}

func NewUDPLookup(servers []string, udpSize uint16) LookupTXTFunc {
	client := new(dns.Client)
	if udpSize == 0 {
		// Running into issues with too small buffer size of dns library in some cases
		client.UDPSize = 4096
	} else {
		client.UDPSize = udpSize
	}
	return func(domain string) (entries []LookupEntry, err error) {
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.RecursionDesired = true
		req.Question = make([]dns.Question, 1)
		req.Question[0] = dns.Question{
			Name:   domain,
			Qtype:  dns.TypeTXT,
			Qclass: dns.ClassINET,
		}
		server := servers[rand.Intn(len(servers))]
		res, _, err := client.Exchange(req, server)
		if err != nil {
			return nil, err
		}
		if res.Rcode != 0 {
			return nil, NewRCodeError(res.Rcode, domain)
		}
		entries = make([]LookupEntry, len(res.Answer))
		for index, answer := range res.Answer {
			if answer.Header().Rrtype == dns.TypeTXT {
				txtAnswer := answer.(*dns.TXT)
				entries[index] = LookupEntry{
					Value: utf8Value(txtAnswer.Txt),
					Ttl:   txtAnswer.Header().Ttl,
				}
			}
		}
		sort.Sort(ByValue{entries})
		return entries, nil
	}
}

const Version = "v0.4.0"
const dnsPrefix = "_dnslink."
const txtPrefix = "dnslink="

var defaultResolver = &Resolver{}

func Resolve(domain string) (Result, error) {
	return defaultResolver.Resolve(domain)
}

func ResolveN(domain string) (Result, error) {
	return defaultResolver.ResolveN(domain)
}

func wrapLookup(r *net.Resolver, ttl uint32) LookupTXTFunc {
	return func(domain string) (res []LookupEntry, err error) {
		txt, err := r.LookupTXT(context.Background(), domain)
		if err != nil {
			if strings.Contains(err.Error(), "no such host") {
				err = NewRCodeError(3, domain)
			}
			return nil, err
		}
		res = make([]LookupEntry, len(txt))
		for index, txt := range txt {
			res[index] = LookupEntry{
				Value: txt,
				// net.LookupTXT doesn't support ttl :-(
				Ttl: ttl,
			}
		}
		return res, nil
	}
}

var defaultLookupTXT = wrapLookup(net.DefaultResolver, 0)

const MAX_UINT_32 uint32 = 4294967295

func resolve(r *Resolver, domain string, recursive bool) (result Result, err error) {
	lookupTXT := r.LookupTXT
	if lookupTXT == nil {
		lookupTXT = defaultLookupTXT
	}
	ttl := MAX_UINT_32
	lookup, error := validateDomain(domain, "")
	result.Links = map[string][]LookupEntry{}
	result.Path = PathEntries{}
	result.Log = []LogStatement{}[:]
	if error != nil {
		return result, error
	}
	chain := make(map[string]bool)
	for {
		domain = lookup.Domain
		resolve := LogStatement{Code: "RESOLVE", Domain: domain, Pathname: lookup.Pathname, Search: lookup.Search}
		txtEntries, error := lookupTXT(domain)
		if error != nil && !(isNotFoundError(error) && strings.HasPrefix(domain, dnsPrefix)) {
			chain[domain] = true
			result.Log = append(result.Log, resolve)
			return result, error
		}
		links, partialLog, redirect, redirectTtl := resolveTxtEntries(domain, recursive, txtEntries)
		result.Log = append(result.Log, partialLog...)
		if redirect == nil {
			result.Log = append(result.Log, resolve)
			for _, entries := range links {
				for i, entry := range entries {
					entry.Ttl = minUint32(entry.Ttl, ttl)
					entries[i] = entry
				}
			}
			result.Links = links
			result.Path = getPathFromLog(result.Log)
			return result, nil
		}
		ttl = minUint32(ttl, redirectTtl)
		if chain[redirect.Domain] {
			result.Log = append(result.Log, resolve, LogStatement{Code: "ENDLESS_REDIRECT", Domain: redirect.Domain, Pathname: redirect.Pathname, Search: redirect.Search})
			return result, nil
		}
		if len(chain) == 31 {
			result.Log = append(result.Log, resolve, LogStatement{Code: "TOO_MANY_REDIRECTS", Domain: redirect.Domain, Pathname: redirect.Pathname, Search: redirect.Search})
			return result, nil
		}
		chain[domain] = true
		result.Log = append(result.Log, LogStatement{Code: "REDIRECT", Domain: lookup.Domain, Pathname: lookup.Pathname, Search: lookup.Search})
		lookup = redirect
	}
}

func minUint32(a uint32, b uint32) (smaller uint32) {
	if a < b {
		return a
	}
	return b
}

func isNotFoundError(err error) bool {
	switch e := err.(type) {
	default:
		return false
	case RCodeError:
		return e.RCode == 3
	}
}

func validateDomain(input string, entry string) (*URLParts, *LogStatement) {
	urlParts := relevantURLParts(input)
	domain := urlParts.Domain
	if strings.HasPrefix(domain, dnsPrefix) {
		domain = domain[len(dnsPrefix):]
		if strings.HasPrefix(domain, dnsPrefix) {
			return nil, &LogStatement{
				Code:     "RECURSIVE_DNSLINK_PREFIX",
				Domain:   urlParts.Domain,
				Entry:    "",
				Reason:   "",
				Pathname: urlParts.Pathname,
				Search:   urlParts.Search,
			}
		}
	}
	domain = strings.TrimSuffix(domain, ".")
	reason := testFqnd(domain)
	if reason != "" {
		return nil, &LogStatement{
			Code:   "INVALID_REDIRECT",
			Entry:  entry,
			Reason: reason,
		}
	}
	return &URLParts{
		Domain:   dnsPrefix + domain,
		Pathname: urlParts.Pathname,
		Search:   urlParts.Search,
	}, nil
}

func testFqnd(domain string) string {
	if len(domain) > 253-9 /* len("_dnslink.") */ {
		return "TOO_LONG"
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		l := len(label)
		if l == 0 {
			return "EMPTY_PART"
		}
		if l > 63 {
			return "TOO_LONG"
		}
	}
	return ""
}

type processedEntry struct {
	value string
	entry string
	ttl   uint32
}

func relevantURLParts(input string) URLParts {
	result, error := url.Parse(input)
	if error != nil {
		return URLParts{
			Domain:   "",
			Pathname: "",
			Search:   map[string][]string{},
		}
	}
	domain := ""
	pathname := ""
	if result.Host != "" {
		domain = result.Host
		pathname = result.Path
	} else if result.Path != "" {
		parts := strings.SplitN(result.Path, "/", 2)
		domain = parts[0]
		if len(parts) == 2 {
			pathname = "/" + parts[1]
		}
	}
	return URLParts{
		Domain:   domain,
		Pathname: escapePath(pathname),
		Search:   searchFromQuery(result.RawQuery),
	}
}

func escapePath(pathname string) string {
	pathparts := strings.Split(pathname, "/")
	for index, pathpart := range pathparts {
		pathparts[index] = url.PathEscape(pathpart)
	}
	return strings.Join(pathparts, "/")
}

func searchFromQuery(query string) map[string][]string {
	search, searchError := url.ParseQuery(query)
	if searchError != nil {
		return make(map[string][]string)
	}
	return search
}

func reducePath(parts []string) string {
	finalParts := []string{}[:]
	for _, part := range parts {
		if part == ".." {
			finalParts = finalParts[:len(finalParts)-1]
		} else if part != "." {
			finalParts = append(finalParts, part)
		}
	}
	for i, part := range finalParts {
		finalParts[i] = url.PathEscape(part)
	}
	return strings.Join(finalParts, "/")
}

func combineSearch(newEntries map[string][]string, search map[string][]string) map[string][]string {
	if len(search) == 0 {
		return newEntries
	}
	for key, entries := range newEntries {
		for _, entry := range entries {
			entryList, hasEntry := search[key]
			if !hasEntry {
				search[key] = []string{entry}
			} else {
				search[key] = append(entryList, entry)
			}
		}
	}
	return search
}

func getPathFromLog(log []LogStatement) (path PathEntries) {
	path = PathEntries{}
	for _, entry := range log {
		if entry.Code != "REDIRECT" && entry.Code != "RESOLVE" {
			continue
		}
		if entry.Pathname != "" || len(entry.Search) != 0 {
			path = append(path, PathEntry{
				Pathname: entry.Pathname,
				Search:   entry.Search,
			})
		}
	}
	// Reverse, see https://stackoverflow.com/a/19239850
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

func resolveTxtEntries(domain string, recursive bool, txtEntries []LookupEntry) (links map[string][]LookupEntry, log []LogStatement, redirect *URLParts, redirectTtl uint32) {
	links = make(map[string][]LookupEntry)
	log = []LogStatement{}[:]
	redirectTtl = MAX_UINT_32
	if !hasDNSLinkEntry(txtEntries) && strings.HasPrefix(domain, dnsPrefix) {
		return links, log, &URLParts{Domain: domain[len(dnsPrefix):]}, redirectTtl
	}
	found, log := processEntries(txtEntries)
	dnsLinks, hasDns := found["dnslink"]
	if recursive && hasDns {
		hasRedirect := false
		var redirect *URLParts
		for _, dns := range dnsLinks {
			validated, error := validateDomain(dns.value, dns.entry)
			if error != nil {
				log = append(log, *error)
			} else if !hasRedirect {
				hasRedirect = true
				redirect = validated
				redirectTtl = dns.ttl
			} else {
				log = append(log, LogStatement{
					Code:  "UNUSED_ENTRY",
					Entry: dns.entry,
				})
			}
		}
		delete(found, "dnslink")
		if hasRedirect {
			for _, foundEntries := range found {
				for _, foundEntry := range foundEntries {
					log = append(log, LogStatement{
						Code:  "UNUSED_ENTRY",
						Entry: foundEntry.entry,
					})
				}
			}
			return links, log, redirect, redirectTtl
		}
	}
	for key, foundEntries := range found {
		list := []LookupEntry{}[:]
		for _, foundEntry := range foundEntries {
			list = append(list, LookupEntry{
				Value: foundEntry.value,
				Ttl:   foundEntry.ttl,
			})
		}
		sort.Sort(ByValue{list})
		links[key] = list
	}
	return links, log, nil, redirectTtl
}

func hasDNSLinkEntry(txtEntries []LookupEntry) bool {
	for _, txtEntry := range txtEntries {
		if strings.HasPrefix(txtEntry.Value, txtPrefix) {
			return true
		}
	}
	return false
}

func processEntries(dnslinkEntries []LookupEntry) (map[string][]processedEntry, []LogStatement) {
	log := []LogStatement{}[:]
	found := make(map[string][]processedEntry)
	for _, entry := range dnslinkEntries {
		if !strings.HasPrefix(entry.Value, txtPrefix) {
			continue
		}
		key, value, error := validateDNSLinkEntry(entry.Value)

		if error != "" {
			log = append(log, LogStatement{Code: "INVALID_ENTRY", Entry: entry.Value, Reason: error})
			continue
		}
		list, hasList := found[key]
		processed := processedEntry{value, entry.Value, entry.Ttl}
		if !hasList {
			found[key] = []processedEntry{processed}
		} else {
			found[key] = append(list, processed)
		}
	}
	return found, log
}

// https://datatracker.ietf.org/doc/html/rfc4343#section-2.1
var entryCharset = regexp.MustCompile("^[\u0020-\u007e]+$")

func validateDNSLinkEntry(entry string) (key string, value string, error string) {
	trimmed := strings.TrimSpace(entry[len(txtPrefix):])
	if !strings.HasPrefix(trimmed, "/") {
		return "", "", "WRONG_START"
	}
	if !entryCharset.MatchString(trimmed) {
		return "", "", "INVALID_CHARACTER"
	}
	trimmed, err := url.PathUnescape(trimmed)
	if err != nil {
		return "", "", "INVALID_ENCODING"
	}
	parts := strings.Split(trimmed, "/")[1:]
	if len(parts) == 0 {
		return "", "", "KEY_MISSING"
	}
	key = strings.TrimSpace(parts[0])
	if key == "" {
		return "", "", "KEY_MISSING"
	}
	if len(parts) == 1 {
		return "", "", "NO_VALUE"
	}
	value = strings.TrimSpace(strings.Join(parts[1:], "/"))
	if value == "" {
		return "", "", "NO_VALUE"
	}
	return key, value, ""
}
