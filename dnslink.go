package dnslink

import (
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strings"

	isd "github.com/jbenet/go-is-domain"
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
	Links map[string][]string `json:"links"`
	Path  []PathEntry         `json:"path"`
	Log   []LogStatement      `json:"log"`
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

type LookupTXTFunc func(name string) (txt []string, err error)

const Version = "v0.0.1"
const dnsPrefix = "_dnslink."
const txtPrefix = "dnslink="

var defaultResolver = &Resolver{}

func Resolve(domain string) (Result, error) {
	return defaultResolver.Resolve(domain)
}

func ResolveN(domain string) (Result, error) {
	return defaultResolver.ResolveN(domain)
}

func resolve(r *Resolver, domain string, recursive bool) (result Result, err error) {
	lookupTXT := r.LookupTXT
	if lookupTXT == nil {
		lookupTXT = net.LookupTXT
	}
	lookup, error := validateDomain(domain)
	result.Links = map[string][]string{}
	result.Path = []PathEntry{}
	result.Log = []LogStatement{}[:]
	if lookup == nil {
		result.Log = append(result.Log, *error)
		return result, nil
	}
	chain := make(map[string]bool)
	for {
		domain = lookup.Domain
		resolve := LogStatement{Code: "RESOLVE", Domain: domain, Pathname: lookup.Pathname, Search: lookup.Search}
		txtEntries, error := lookupTXT(domain)
		if error != nil && !strings.HasPrefix(domain, dnsPrefix) {
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

func validateDomain(input string) (*URLParts, *LogStatement) {
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
	if !isd.IsDomain(domain) {
		return nil, &LogStatement{
			Code:     "INVALID_REDIRECT",
			Domain:   urlParts.Domain,
			Pathname: urlParts.Pathname,
			Search:   urlParts.Search,
		}
	}
	return &URLParts{
		Domain:   dnsPrefix + domain,
		Pathname: urlParts.Pathname,
		Search:   urlParts.Search,
	}, nil
}

type processedEntry struct {
	value string
	entry string
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

func resolveTxtEntries(domain string, recursive bool, txtEntries []string) (links map[string][]string, log []LogStatement, redirect *URLParts) {
	links = make(map[string][]string)
	log = []LogStatement{}[:]
	if !hasDNSLinkEntry(txtEntries) && strings.HasPrefix(domain, dnsPrefix) {
		return links, log, &URLParts{Domain: domain[len(dnsPrefix):]}
	}
	found, log := processEntries(txtEntries)
	dnsLinks, hasDns := found["dns"]
	if recursive && hasDns {
		hasRedirect := false
		var redirect *URLParts
		for _, dns := range dnsLinks {
			validated, error := validateDomain(dns.value)
			if error != nil {
				delete(found, "dns")
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
		if hasRedirect {
			for key, foundEntries := range found {
				if key == "dns" {
					continue
				}
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
		list := []string{}[:]
		for _, foundEntry := range foundEntries {
			list = append(list, foundEntry.value)
		}
		sort.Strings(list)
		links[key] = list
	}
	return links, log, nil
}

func hasDNSLinkEntry(txtEntries []string) bool {
	for _, txtEntry := range txtEntries {
		if strings.HasPrefix(txtEntry, txtPrefix) {
			return true
		}
	}
	return false
}

func processEntries(dnslinkEntries []string) (map[string][]processedEntry, []LogStatement) {
	log := []LogStatement{}[:]
	found := make(map[string][]processedEntry)
	for _, entry := range dnslinkEntries {
		if !strings.HasPrefix(entry, txtPrefix) {
			continue
		}
		key, value, error := validateDNSLinkEntry(entry)

		if error != "" {
			log = append(log, LogStatement{Code: "INVALID_ENTRY", Entry: entry, Reason: error})
			continue
		}
		list, hasList := found[key]
		processed := processedEntry{value, entry}
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
