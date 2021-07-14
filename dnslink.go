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

type PathEntry struct {
	Pathname string
	Search   map[string][]string
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

type LogStatement struct {
	Code     string
	Domain   string
	Entry    string
	Reason   string
	Pathname string
	Search   map[string][]string
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
	Path  []PathEntry              `json:"path"`
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

const Version = "v0.2.0"
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

func resolve(r *Resolver, domain string, recursive bool) (result Result, err error) {
	lookupTXT := r.LookupTXT
	if lookupTXT == nil {
		lookupTXT = defaultLookupTXT
	}
	lookup, error := validateDomain(domain, "")
	result.Links = map[string][]LookupEntry{}
	result.Path = []PathEntry{}
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
		links, partialLog, redirect := resolveTxtEntries(domain, recursive, txtEntries)
		result.Log = append(result.Log, partialLog...)
		if redirect == nil {
			result.Log = append(result.Log, resolve)
			result.Links = links
			result.Path = getPathFromLog(result.Log)
			return result, nil
		}
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
	if !isFqdn(domain) {
		return nil, &LogStatement{
			Code:  "INVALID_REDIRECT",
			Entry: entry,
		}
	}
	domain = strings.TrimSuffix(domain, ".")
	return &URLParts{
		Domain:   dnsPrefix + domain,
		Pathname: urlParts.Pathname,
		Search:   urlParts.Search,
	}, nil
}

var intlDomainCharset = regexp.MustCompile("^([a-z\u00a1-\uffff]{2,}|xn[a-z0-9-]{2,})$")
var spacesAndSpecialChars = regexp.MustCompile("[\\s\u2002-\u200B\u202F\u205F\u3000��\u00A9\uFFFD\uFEFF]")
var domainCharset = regexp.MustCompile("^[a-z\u00a1-\u00ff0-9-]+$")

func isFqdn(str string) bool {
	str = strings.TrimSuffix(str, ".")
	if str == "" {
		return false
	}
	parts := strings.Split(str, ".")
	tld := parts[len(parts)-1]

	// disallow fqdns without tld
	if len(parts) < 2 {
		return false
	}

	if !intlDomainCharset.MatchString(tld) {
		return false
	}

	// disallow spaces && special characers
	if spacesAndSpecialChars.MatchString(tld) {
		return false
	}

	// disallow all numbers
	if every(parts, isNumber) {
		return false
	}

	return every(parts, isDomainPart)
}

func isDomainPart(part string) bool {
	if len(part) > 63 {
		return false
	}

	if !domainCharset.MatchString(part) {
		return false
	}

	// disallow parts starting or ending with hyphen
	if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
		return false
	}

	return true
}

func isNumber(str string) bool {
	_, err := strconv.Atoi(str)
	return err == nil
}

func every(strings []string, test func(string) bool) bool {
	for _, str := range strings {
		if !test(str) {
			return false
		}
	}
	return true
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
	pathparts := strings.Split(pathname, "/")
	for index, pathpart := range pathparts {
		pathparts[index] = url.PathEscape(pathpart)
	}
	pathname = strings.Join(pathparts, "/")
	search, searchError := url.ParseQuery(result.RawQuery)
	if searchError != nil {
		search = make(map[string][]string)
	}
	return URLParts{
		Domain:   domain,
		Pathname: pathname,
		Search:   search,
	}
}

func getPathFromLog(log []LogStatement) []PathEntry {
	path := []PathEntry{}[:]
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

func resolveTxtEntries(domain string, recursive bool, txtEntries []LookupEntry) (links map[string][]LookupEntry, log []LogStatement, redirect *URLParts) {
	links = make(map[string][]LookupEntry)
	log = []LogStatement{}[:]
	if !hasDNSLinkEntry(txtEntries) && strings.HasPrefix(domain, dnsPrefix) {
		return links, log, &URLParts{Domain: domain[len(dnsPrefix):]}
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
			return links, log, redirect
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
	return links, log, nil
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

func validateDNSLinkEntry(entry string) (key string, value string, error string) {
	trimmed := strings.TrimSpace(entry[len(txtPrefix):])
	if !strings.HasPrefix(trimmed, "/") {
		return "", "", "WRONG_START"
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
