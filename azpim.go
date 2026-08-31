// Package azpim activates and deactivates Azure PIM assignments from the
// command line.
//
// Only the signed-in user's own assignments are in scope. PIM activation is a
// "selfActivate" operation, so it is meaningful solely in a delegated context;
// there is deliberately no app-only authentication here.
//
// Entra ID directory roles and PIM for Groups live behind separate Microsoft
// Graph APIs and separate consent scopes, so each command asks only for the
// scopes its own area needs. A tenant that has consented to one area therefore
// keeps working in that area even if the other is unavailable.
package azpim

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// DefaultClientID is the Microsoft Graph PowerShell first-party application.
//
// The Azure CLI application cannot be used: the delegated Graph scopes
// Microsoft grants it are fixed and contain nothing from PIM, so no amount of
// re-authenticating produces a usable token. Graph PowerShell is a public
// client that exists in every tenant and is the app `Connect-MgGraph` signs in
// through, which makes it the one identity a PIM tool can rely on without
// registering an application. Running it does not require PowerShell itself.
//
// Sign-ins are recorded against this application, and it only ever yields
// scopes the tenant has already consented to. Override with --client-id to sign
// in through an application of your own.
const DefaultClientID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

// Context carries the streams commands write to and the way they reach Graph.
//
// Tables go to Output so they can be piped; everything else goes to ErrOutput
// so that progress and results never contaminate that data.
type Context struct {
	Output    io.Writer
	ErrOutput io.Writer

	// Graph returns a client authenticated for exactly the given scopes.
	// Sign-in is deferred to here rather than done up front so that --help and
	// argument errors never open a browser.
	Graph func(ctx context.Context, scopes []string) (*Client, error)
}

// writeTable renders rows under a header, padded into columns.
//
// A destination that cannot be written to is not something a command can do
// anything about, so the writes are not checked.
func writeTable(w io.Writer, header []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, strings.Join(header, "\t")) //nolint:errcheck

	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t")) //nolint:errcheck
	}

	tw.Flush() //nolint:errcheck
}

// matchOne picks the single item whose name contains query, ignoring case.
//
// Activating the wrong role is not a mistake worth being relaxed about, so an
// ambiguous query is an error listing the candidates rather than a guess at
// which one was meant.
func matchOne[T any](items []T, query string, name func(T) string) (T, error) {
	var zero T

	hits := []T{}

	for _, item := range items {
		if strings.Contains(strings.ToLower(name(item)), strings.ToLower(query)) {
			hits = append(hits, item)
		}
	}

	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return zero, fmt.Errorf("no eligible assignment matches %q; run the list command to see what is available", query)
	default:
		names := make([]string, len(hits))
		for i, hit := range hits {
			names[i] = name(hit)
		}

		return zero, fmt.Errorf("%q matches more than one eligible assignment: %s", query, strings.Join(names, ", "))
	}
}
