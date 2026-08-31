package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveVersion(t *testing.T) {
	assert := assert.New(t)

	// A stamped version is used as it is.
	assert.Equal("1.2.3", resolveVersion("1.2.3"))

	// Without one, the answer comes from what the toolchain embedded, which
	// depends on how this binary was built. What matters is that --version
	// says something rather than printing an empty line.
	assert.NotEmpty(resolveVersion(""))
}
