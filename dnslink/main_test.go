package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	a := assert.New(t)
	options, rest := getOptions([]string{"hello"})
	a.EqualValues(options, Options{})
	a.EqualValues(rest, []string{"hello"})
	options, _ = getOptions([]string{"--hello"})
	a.EqualValues(options.get("hello"), []interface{}{true})
	a.True(options.has("hello"))
	options, _ = getOptions([]string{"-hello", "--hello=world"})
	a.EqualValues(options.get("hello"), []interface{}{true, "world"})
}
