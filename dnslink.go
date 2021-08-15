package dnslink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	dns "github.com/miekg/dns"
)

type LogStatement struct {
	Code   string
	Entry  string
	Reason string
}

func (l *LogStatement) Error() string {
	return l.Code
}

func (stmt *LogStatement) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{
		"code": stmt.Code,
	}
	if stmt.Entry != "" {
		out["entry"] = stmt.Entry
	}
	if stmt.Reason != "" {
		out["reason"] = stmt.Reason
	}
	return json.Marshal(out)
}

type Result struct {
	Links map[string][]NamespaceEntry `json:"links"`
	Log   []LogStatement              `json:"log"`
}

type NamespaceEntry struct {
	Identifier string `json:"identifier"`
	Ttl        uint32 `json:"ttl"`
}

type Resolver struct {
	LookupTXT LookupTXTFunc
}

func (r *Resolver) Resolve(domain string) (Result, error) {
	return resolve(r, domain)
}

type LookupEntry struct {
	Value string
	Ttl   uint32
}
type NamespaceEntries []NamespaceEntry

func (l NamespaceEntries) Len() int      { return len(l) }
func (l NamespaceEntries) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

type ByValue struct{ NamespaceEntries }

func (s ByValue) Less(i, j int) bool {
	return s.NamespaceEntries[i].Identifier < s.NamespaceEntries[j].Identifier
}

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

func resolve(r *Resolver, domain string) (result Result, err error) {
	lookupTXT := r.LookupTXT
	if lookupTXT == nil {
		lookupTXT = defaultLookupTXT
	}
	domain = strings.TrimPrefix(domain, dnsPrefix)
	domain = strings.TrimSuffix(domain, ".")
	err = testFqnd(domain)
	if err != nil {
		return
	}
	fallback := false
	txtEntries, err := lookupTXT(dnsPrefix + domain)
	if err != nil {
		if isNotFoundError(err) {
			txtEntries, err = lookupTXT(domain)
			if err != nil {
				return
			}
			fallback = true
		} else {
			return
		}
	}
	links, log := processEntries(txtEntries)
	if fallback {
		log = append([]LogStatement{{Code: "FALLBACK"}}, log...)
	}
	result.Log = log
	result.Links = links
	return
}

func isNotFoundError(err error) bool {
	switch e := err.(type) {
	default:
		return false
	case RCodeError:
		return e.RCode == 3
	}
}

func testFqnd(domain string) error {
	if len(domain) > 253-9 /* len("_dnslink.") */ {
		return errors.New("TOO_LONG")
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		l := len(label)
		if l == 0 {
			return errors.New("EMPTY_PART")
		}
		if l > 63 {
			return errors.New("TOO_LONG")
		}
	}
	return nil
}

func processEntries(dnslinkEntries []LookupEntry) (map[string][]NamespaceEntry, []LogStatement) {
	log := []LogStatement{}[:]
	found := make(map[string][]NamespaceEntry)
	for _, entry := range dnslinkEntries {
		if !strings.HasPrefix(entry.Value, txtPrefix) {
			continue
		}
		key, value, reason := validateDNSLinkEntry(entry.Value)

		if reason != "" {
			log = append(log, LogStatement{Code: "INVALID_ENTRY", Entry: entry.Value, Reason: reason})
			continue
		}
		list, hasList := found[key]
		processed := NamespaceEntry{value, entry.Ttl}
		if !hasList {
			found[key] = []NamespaceEntry{processed}
		} else {
			found[key] = append(list, processed)
		}
	}
	for _, list := range found {
		sort.Sort(ByValue{list})
	}
	return found, log
}

// https://datatracker.ietf.org/doc/html/rfc4343#section-2.1
var entryCharset = regexp.MustCompile("^[\u0020-\u007e]+$")

func validateDNSLinkEntry(entry string) (namespace string, identifier string, reason string) {
	trimmed := strings.TrimSpace(entry[len(txtPrefix):])
	if !strings.HasPrefix(trimmed, "/") {
		return "", "", "WRONG_START"
	}
	if !entryCharset.MatchString(trimmed) {
		return "", "", "INVALID_CHARACTER"
	}
	parts := strings.Split(trimmed, "/")[1:]
	if len(parts) == 0 {
		return "", "", "NAMESPACE_MISSING"
	}
	namespace = strings.TrimSpace(parts[0])
	if namespace == "" {
		return "", "", "NAMESPACE_MISSING"
	}
	if len(parts) == 1 {
		return "", "", "NO_IDENTIFIER"
	}
	identifier = strings.TrimSpace(strings.Join(parts[1:], "/"))
	if identifier == "" {
		return "", "", "NO_IDENTIFIER"
	}
	return namespace, identifier, ""
}
