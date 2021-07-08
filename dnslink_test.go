package dnslink

import (
	"fmt"
	"testing"

	"github.com/go-test/deep"
	assert "github.com/stretchr/testify/assert"
)

type mockDNS struct {
	entries map[string][]string
}

func (m *mockDNS) lookupTXT(name string) (res []LookupEntry, err error) {
	txt, ok := m.entries[name]
	if !ok {
		return nil, fmt.Errorf("No TXT entry for %s", name)
	}
	res = make([]LookupEntry, len(txt))
	for index, entry := range txt {
		res[index] = LookupEntry{
			Value: entry,
			Ttl:   100,
		}
	}
	return res, nil
}

func newMockDNS() *mockDNS {
	return &mockDNS{
		entries: map[string][]string{
			"foo.com":            {"dnslink=/dns/bar.com/foo/f/o/o"},
			"bar.com":            {"dnslink=/dns/test.it.baz.com/bar/b/a/r"},
			"test.it.baz.com":    {"dnslink=/baz/b/a/z"},
			"ipfs.example.com":   {"dnslink=/ipfs/QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD"},
			"dns1.example.com":   {"dnslink=/dns/ipfs.example.com"},
			"dns2.example.com":   {"dnslink=/dns/dns1.example.com"},
			"equals.example.com": {"dnslink=/ipfs/QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD/=equals"},
			"loop1.example.com":  {"dnslink=/dns/loop2.example.com"},
			"loop2.example.com":  {"dnslink=/dns/loop1.example.com"},
			"bad.example.com":    {"dnslink="},
			"multi.example.com": {
				"some stuff",
				"dnslink=/dns/dns1.example.com",
				"masked dnslink=/dns/example.invalid",
			},
		},
	}
}

func TestRelevantURLParts(t *testing.T) {
	assertResult(t, arr(relevantURLParts("hello")), URLParts{
		Domain:   "hello",
		Pathname: "",
		Search:   make(map[string][]string),
	})
	assertResult(t, arr(relevantURLParts("hello.com/foo")), URLParts{
		Domain:   "hello.com",
		Pathname: "/foo",
		Search:   make(map[string][]string),
	})
	assertResult(t, arr(relevantURLParts("https://hello.com/foo/fou?bar=baz&bar=bak&car=caz")), URLParts{
		Domain:   "hello.com",
		Pathname: "/foo/fou",
		Search: map[string][]string{
			"bar": {"baz", "bak"},
			"car": {"caz"},
		},
	})
}

func TestValidateDomain(t *testing.T) {
	var logNil *LogStatement = nil
	var partsNil *URLParts = nil
	assertResult(t, arr(validateDomain("hello.com")),
		&URLParts{Domain: "_dnslink.hello.com", Pathname: "", Search: make(map[string][]string)},
		logNil,
	)
	assertResult(t, arr(validateDomain("_dnslink.hello.com/foo?bar=baz")),
		&URLParts{Domain: "_dnslink.hello.com", Pathname: "/foo", Search: map[string][]string{"bar": {"baz"}}},
		logNil,
	)
	assertResult(t, arr(validateDomain("hello .com")),
		partsNil,
		&LogStatement{Code: "INVALID_REDIRECT", Domain: "hello .com", Pathname: "", Search: make(map[string][]string)},
	)
	assertResult(t, arr(validateDomain("_dnslink._dnslink.hello.com")),
		partsNil,
		&LogStatement{Code: "RECURSIVE_DNSLINK_PREFIX", Domain: "_dnslink._dnslink.hello.com", Pathname: "", Search: make(map[string][]string)},
	)
}

func TestValidateDNSLinkEntry(t *testing.T) {
	assertResult(t, arr(validateDNSLinkEntry("dnslink=")), "", "", "WRONG_START")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/")), "", "", "KEY_MISSING")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=//")), "", "", "KEY_MISSING")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/abcd/")), "", "", "NO_VALUE")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/abcd/efgh")), "abcd", "efgh", "")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/ abcd /  efgh ")), "abcd", "efgh", "")
}

func TestProcessEntries(t *testing.T) {
	assertResult(t, arr(processEntries([]LookupEntry{})), map[string][]processedEntry{}, []LogStatement{})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "foo", Ttl: 100},
			{Value: "dnslink=", Ttl: 100},
		})),
		map[string][]processedEntry{}, []LogStatement{
			{Code: "INVALID_ENTRY", Entry: "dnslink=", Reason: "WRONG_START"},
		})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
		})),
		map[string][]processedEntry{"foo": {
			{value: "bar", entry: "dnslink=/foo/bar"},
		}}, []LogStatement{})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
			{Value: "dnslink=/foo/baz", Ttl: 100},
		})),
		map[string][]processedEntry{"foo": {
			{value: "bar", entry: "dnslink=/foo/bar"},
			{value: "baz", entry: "dnslink=/foo/baz"},
		}}, []LogStatement{})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
			{Value: "dnslink=/foo/baz", Ttl: 100},
		})),
		map[string][]processedEntry{"foo": {
			{value: "bar", entry: "dnslink=/foo/bar"},
			{value: "baz", entry: "dnslink=/foo/baz"},
		}}, []LogStatement{})
}

func TestResolveTxtEntries(t *testing.T) {
	var partsNil *URLParts = nil
	assertResult(t, arr(resolveTxtEntries("domain.com", true, []LookupEntry{})), map[string][]string{}, []LogStatement{}, partsNil)
	assertResult(t, arr(resolveTxtEntries("_dnslink.domain.com", true, []LookupEntry{})), map[string][]string{}, []LogStatement{}, &URLParts{Domain: "domain.com"})
	assertResult(t,
		arr(resolveTxtEntries("_dnslink.domain.com", true, []LookupEntry{
			{Value: "foo", Ttl: 100},
		})),
		map[string][]string{}, []LogStatement{}, &URLParts{Domain: "domain.com"})
	assertResult(t,
		arr(resolveTxtEntries("domain.com", true, []LookupEntry{
			{Value: "dnslink=", Ttl: 100},
		})),
		map[string][]string{}, []LogStatement{
			{Code: "INVALID_ENTRY", Entry: "dnslink=", Reason: "WRONG_START"},
		}, partsNil)
	assertResult(t,
		arr(resolveTxtEntries("_dnslink.domain.com", true, []LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
		})),
		map[string][]string{"foo": {"bar"}}, []LogStatement{}, partsNil)
	assertResult(t,
		arr(resolveTxtEntries("_dnslink.domain.com", true, []LookupEntry{
			{Value: "dnslink=/dns/domain-b.com", Ttl: 100},
		})),
		map[string][]string{}, []LogStatement{}, &URLParts{
			Domain: "_dnslink.domain-b.com",
			Search: make(map[string][]string),
		})
	assertResult(t,
		arr(resolveTxtEntries("_dnslink.domain.com", true, []LookupEntry{
			{Value: "dnslink=/dns/domain b.com", Ttl: 100},
		})),
		map[string][]string{}, []LogStatement{
			{Code: "INVALID_REDIRECT", Domain: "domain b.com", Search: make(map[string][]string)},
		}, partsNil)
	assertResult(t,
		arr(resolveTxtEntries("_dnslink.domain.com", true, []LookupEntry{
			{Value: "dnslink=/dns/domain-b.com", Ttl: 100},
			{Value: "dnslink=/foo/bar", Ttl: 100},
		})),
		map[string][]string{}, []LogStatement{
			{Code: "UNUSED_ENTRY", Entry: "dnslink=/foo/bar"},
		}, &URLParts{
			Domain: "_dnslink.domain-b.com",
			Search: make(map[string][]string),
		})
}

func TestGetPathFromLog(t *testing.T) {
	a := assert.New(t)
	a.EqualValues(getPathFromLog([]LogStatement{}), []PathEntry{})
	a.EqualValues(getPathFromLog([]LogStatement{{Code: "RESOLVE", Pathname: "/foo/bar"}}), []PathEntry{
		{Pathname: "/foo/bar"},
	})
	a.EqualValues(getPathFromLog([]LogStatement{
		{Code: "REDIRECT", Pathname: "/foo/bar", Search: map[string][]string{"foo": {"bar", "baz"}}},
		{Code: "REDIRECT", Pathname: "/too/tar", Search: map[string][]string{"too": {"tar", "taz"}}},
		{Code: "RESOLVE", Pathname: "/baz/bak"},
	}), []PathEntry{
		{Pathname: "/baz/bak"},
		{Pathname: "/too/tar", Search: map[string][]string{"too": {"tar", "taz"}}},
		{Pathname: "/foo/bar", Search: map[string][]string{"foo": {"bar", "baz"}}},
	})
}

func TestDnsLinkN(t *testing.T) {
	mock := newMockDNS()
	r := &Resolver{LookupTXT: mock.lookupTXT}
	result := arr(r.ResolveN("ipfs.example.com"))
	assertResult(t, result, Result{
		Links: map[string][]LookupEntry{
			"ipfs": {
				{Value: "QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD"},
			},
		},
		Path: []PathEntry{},
		Log: []LogStatement{
			{Code: "REDIRECT", Domain: "_dnslink.ipfs.example.com", Search: map[string][]string{}},
			{Code: "RESOLVE", Domain: "ipfs.example.com"},
		},
	}, nil)
}

func TestUDPLookup(t *testing.T) {
	lookup := NewUDPLookup([]string{"1.1.1.1:53"})
	txt, error := lookup("_dnslink.t05.dnslink.dev")
	assert.NoError(t, error)
	assert.Equal(t, len(txt), 2)
	assert.Equal(t, txt[0].Value, "dnslink=/ipfs/")
	assert.Equal(t, txt[1].Value, "dnslink=/ipfs/MNOP")
	assert.InDelta(t, txt[0].Ttl, 1800, 1802) // 0 ~ 3600 + margin
}

func arr(input ...interface{}) []interface{} {
	return input
}

func assertResult(t *testing.T, result []interface{}, expected ...interface{}) {
	assertDeepEqual(t, result, expected)
}

func assertDeepEqual(t *testing.T, a interface{}, b interface{}) {
	if diff := deep.Equal(a, b); diff != nil {
		t.Error(diff)
	}
}
