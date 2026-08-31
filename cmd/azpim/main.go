package main

import (
	"context"
	"os"

	"github.com/alecthomas/kong"
	"github.com/winebarrel/azpim"
)

var version string

var cli struct {
	Version kong.VersionFlag

	TenantID string   `env:"AZPIM_TENANT_ID" default:"organizations" help:"Tenant to sign in to."`
	ClientID string   `env:"AZPIM_CLIENT_ID" default:"${defaultClientID}" help:"Application to sign in through."`
	Scope    []string `env:"AZPIM_SCOPE" help:"Delegated scopes to request instead of the ones the command would ask for."`

	Role  azpim.RoleCmd  `cmd:"" help:"Manage Microsoft Entra ID directory role assignments."`
	Group azpim.GroupCmd `cmd:"" help:"Manage PIM for Groups assignments."`
}

func main() {
	kctx := kong.Parse(&cli,
		kong.Name("azpim"),
		kong.Description("Activate and deactivate your own Azure PIM assignments."),
		kong.Vars{
			"version":         version,
			"defaultClientID": azpim.DefaultClientID,
		},
	)

	auth := &azpim.Authenticator{
		TenantID:  cli.TenantID,
		ClientID:  cli.ClientID,
		ErrOutput: os.Stderr,
	}

	err := kctx.Run(&azpim.Context{
		Output:    os.Stdout,
		ErrOutput: os.Stderr,
		Graph: func(ctx context.Context, scopes []string) (*azpim.Client, error) {
			// A tenant may have consented to a different set than the command
			// would ask for, so --scope replaces the request wholesale rather
			// than adding to it.
			if len(cli.Scope) > 0 {
				scopes = cli.Scope
			}

			return auth.Client(ctx, scopes)
		},
	})

	kctx.FatalIfErrorf(err)
}
