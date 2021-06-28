package dnslink

import (
	"net"
	"net/url"
	"strings"

	isd "github.com/jbenet/go-is-domain"
)

type PathEntry struct {
	Pathname string              `json:"pathname"`
	Search   map[string][]string `json:"search"`
}

type LogStatement struct {
	Code     string              `json:"code"`
	Domain   string              `json:"domain"`
	Entry    string              `json:"entry"`
	Reason   string              `json:"reason"`
	Pathname string              `json:"pathname"`
	Search   map[string][]string `json:"search"`
}

type Result struct {
	Links map[string]string `json:"links"`
	Path  []PathEntry       `json:"path"`
	Log   []LogStatement    `json:"log"`
}
type URLParts struct {
	Domain   string              `json:"domain"`
	Pathname string              `json:"pathname"`
	Search   map[string][]string `json:"search"`
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

const dnsPrefix = "_dnslink."
const txtPrefix = "dnslink="

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

func (r *Resolver) Resolve(domain string) (Result, error) {
	return r.resolve(domain, false)
}

func (r *Resolver) ResolveN(domain string) (Result, error) {
	return r.resolve(domain, true)
}

func (r *Resolver) resolve(domain string, recursive bool) (result Result, err error) {
	r.setDefaults()
	lookup, error := validateDomain(domain)
	result.Links = map[string]string{}
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
		txtEntries, error := r.LookupTXT(domain)
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

func resolveTxtEntries(domain string, recursive bool, txtEntries []string) (links map[string]string, log []LogStatement, redirect *URLParts) {
	links = make(map[string]string)
	log = []LogStatement{}[:]
	if !hasDNSLinkEntry(txtEntries) && strings.HasPrefix(domain, dnsPrefix) {
		return links, log, &URLParts{Domain: domain[len(dnsPrefix):]}
	}
	found, log := processEntries(txtEntries)
	dns, hasDns := found["dns"]
	if recursive && hasDns {
		redirect, error := validateDomain(dns.value)
		if error != nil {
			delete(found, "dns")
			log = append(log, *error)
		} else {
			for key, foundEntry := range found {
				if key == "dns" {
					continue
				}
				log = append(log, LogStatement{
					Code:  "UNUSED_ENTRY",
					Entry: foundEntry.entry,
				})
			}
			return links, log, redirect
		}
	}
	for key, foundEntry := range found {
		links[key] = foundEntry.value
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

func processEntries(dnslinkEntries []string) (map[string]processedEntry, []LogStatement) {
	log := []LogStatement{}[:]
	found := make(map[string]processedEntry)
	for _, entry := range dnslinkEntries {
		if !strings.HasPrefix(entry, txtPrefix) {
			continue
		}
		key, value, error := validateDNSLinkEntry(entry)

		if error != "" {
			log = append(log, LogStatement{Code: "INVALID_ENTRY", Entry: entry, Reason: error})
			continue
		}
		prev, hasPrev := found[key]
		if !hasPrev || strings.Compare(prev.value, value) > 0 {
			if hasPrev {
				log = append(log, LogStatement{Code: "CONFLICT_ENTRY", Entry: prev.entry})
			}
			found[key] = processedEntry{value, entry}
		} else {
			log = append(log, LogStatement{Code: "CONFLICT_ENTRY", Entry: entry})
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

type LookupTXTFunc func(name string) (txt []string, err error)

func Resolve(domain string) (Result, error) {
	return defaultResolver.Resolve(domain)
}

func ResolveN(domain string) (Result, error) {
	return defaultResolver.ResolveN(domain)
}

type Resolver struct {
	LookupTXT LookupTXTFunc
}

var defaultResolver = &Resolver{}

func NewResolver() *Resolver {
	return &Resolver{net.LookupTXT}
}

func (r *Resolver) setDefaults() {
	// check internal params
	if r.LookupTXT == nil {
		r.LookupTXT = net.LookupTXT
	}
}
