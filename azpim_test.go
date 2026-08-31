package azpim_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/winebarrel/azpim"
)

// commands names every subcommand along with a way to run it, so that a
// concern common to all of them can be checked against all of them.
func commands() map[string]func(*azpim.Context) error {
	return map[string]func(*azpim.Context) error{
		"role list":        func(c *azpim.Context) error { return (&azpim.RoleListCmd{}).Run(c) },
		"role active":      func(c *azpim.Context) error { return (&azpim.RoleActiveCmd{}).Run(c) },
		"role requests":    func(c *azpim.Context) error { return (&azpim.RoleRequestsCmd{Limit: 5}).Run(c) },
		"role activate":    func(c *azpim.Context) error { return (&azpim.RoleActivateCmd{Role: "x", Duration: "1h"}).Run(c) },
		"role deactivate":  func(c *azpim.Context) error { return (&azpim.RoleDeactivateCmd{Role: "x"}).Run(c) },
		"group list":       func(c *azpim.Context) error { return (&azpim.GroupListCmd{}).Run(c) },
		"group active":     func(c *azpim.Context) error { return (&azpim.GroupActiveCmd{}).Run(c) },
		"group requests":   func(c *azpim.Context) error { return (&azpim.GroupRequestsCmd{Limit: 5}).Run(c) },
		"group activate":   func(c *azpim.Context) error { return (&azpim.GroupActivateCmd{Group: "x", Duration: "1h"}).Run(c) },
		"group deactivate": func(c *azpim.Context) error { return (&azpim.GroupDeactivateCmd{Group: "x"}).Run(c) },
	}
}

// TestCommandsReportSignInFailure covers a sign-in that never produces a
// client. Every command has to surface that rather than carry on without one.
func TestCommandsReportSignInFailure(t *testing.T) {
	for name, run := range commands() {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			cmdCtx := &azpim.Context{
				Output:    &bytes.Buffer{},
				ErrOutput: &bytes.Buffer{},
				Graph: func(context.Context, []string) (*azpim.Client, error) {
					return nil, errors.New("sign-in was blocked")
				},
			}

			assert.ErrorContains(run(cmdCtx), "sign-in was blocked")
		})
	}
}

// TestCommandsReportGraphFailure covers Graph refusing every call, which is
// what a token missing the right scopes looks like from here.
func TestCommandsReportGraphFailure(t *testing.T) {
	denied := `403|{"error":{"code":"UnknownError",` +
		`"message":"{\"errorCode\":\"PermissionScopeNotGranted\",\"message\":\"nope\"}"}}`

	for name, run := range commands() {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			stub := newGraphStub(t, map[string]string{
				"roleManagement":   denied,
				"privilegedAccess": denied,
			})

			err := run(stub.context(&bytes.Buffer{}, &bytes.Buffer{}))

			assert.ErrorContains(err, "PermissionScopeNotGranted")
		})
	}
}
