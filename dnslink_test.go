package dnslink

import (
	"errors"
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
		return nil, NewRCodeError(3, fmt.Sprintf("No TXT entry for %s", name))
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
			"foo.com":          {"dnslink=/x/a"},
			"_dnslink.bar.com": {"dnslink=/y/b"},
		},
	}
}

func TestValidateDomain(t *testing.T) {
	assertResult(t, arr(testFqnd("hello..com")),
		errors.New("EMPTY_PART"),
	)
}

func TestValidateDNSLinkEntry(t *testing.T) {
	assertResult(t, arr(validateDNSLinkEntry("dnslink=")), "", "", "WRONG_START")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/")), "", "", "NAMESPACE_MISSING")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=//")), "", "", "NAMESPACE_MISSING")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/abcd/")), "", "", "NO_IDENTIFIER")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/abcd/efgh")), "abcd", "efgh", "")
	assertResult(t, arr(validateDNSLinkEntry("dnslink=/ abcd /  efgh ")), "abcd", "efgh", "")
}

func TestProcessEntries(t *testing.T) {
	assertResult(t, arr(processEntries([]LookupEntry{})), map[string][]LookupEntry{}, []LogStatement{})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "foo", Ttl: 100},
			{Value: "dnslink=", Ttl: 100},
		})),
		map[string]NamespaceEntries{}, []LogStatement{
			{Code: "INVALID_ENTRY", Entry: "dnslink=", Reason: "WRONG_START"},
		})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
		})),
		map[string]NamespaceEntries{"foo": {
			{Identifier: "bar", Ttl: 100},
		}}, []LogStatement{})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
			{Value: "dnslink=/foo/baz", Ttl: 100},
		})),
		map[string]NamespaceEntries{"foo": {
			{Identifier: "bar", Ttl: 100},
			{Identifier: "baz", Ttl: 100},
		}}, []LogStatement{})
	assertResult(t,
		arr(processEntries([]LookupEntry{
			{Value: "dnslink=/foo/bar", Ttl: 100},
			{Value: "dnslink=/foo/baz", Ttl: 100},
		})),
		map[string]NamespaceEntries{"foo": {
			{Identifier: "bar", Ttl: 100},
			{Identifier: "baz", Ttl: 100},
		}}, []LogStatement{})
}

func TestDnsLink(t *testing.T) {
	mock := newMockDNS()
	r := &Resolver{LookupTXT: mock.lookupTXT}
	assertResult(t, arr(r.Resolve("foo.com")), Result{
		Links: map[string][]NamespaceEntry{
			"x": {{Identifier: "a", Ttl: 100}},
		},
		Log: []LogStatement{
			{Code: "FALLBACK"},
		},
	}, nil)
	assertResult(t, arr(r.Resolve("bar.com")), Result{
		Links: map[string][]NamespaceEntry{
			"y": {{Identifier: "b", Ttl: 100}},
		},
		Log: []LogStatement{},
	}, nil)
}

func TestUDPLookup(t *testing.T) {
	lookup := NewUDPLookup([]string{"1.1.1.1:53"}, 0)
	txt, error := lookup("dnslink.dev")
	assert.NoError(t, error)
	assert.Equal(t, len(txt), 1)
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
