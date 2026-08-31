package azpim_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/winebarrel/azpim"
)

func TestVersion(t *testing.T) {
	assert := assert.New(t)

	// A stamped version is used as it is.
	assert.Equal("1.2.3", azpim.Version("1.2.3"))

	// Without one, the answer comes from what the toolchain embedded, which
	// depends on how this binary was built. What matters is that --version
	// says something rather than printing an empty line.
	assert.NotEmpty(azpim.Version(""))
}
