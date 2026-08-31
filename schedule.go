package azpim

import (
	"fmt"
	"time"
)

// scheduleInfo says when an activation starts and how long it lasts.
type scheduleInfo struct {
	StartDateTime string     `json:"startDateTime"`
	Expiration    expiration `json:"expiration"`
}

type expiration struct {
	Type     string `json:"type"`
	Duration string `json:"duration"`
}

// newScheduleInfo asks for an activation starting now.
//
// The start is sent explicitly rather than left to the service to default, so
// that the window is anchored to when the request was made instead of to
// whenever it happens to be processed.
func newScheduleInfo(duration string) *scheduleInfo {
	return &scheduleInfo{
		StartDateTime: time.Now().UTC().Format(time.RFC3339),
		Expiration:    expiration{Type: "AfterDuration", Duration: duration},
	}
}

// displayScope renders a directory scope for a table. The tenant root is "/",
// which reads as noise in a column.
func displayScope(scope string) string {
	if scope == "/" || scope == "" {
		return "tenant"
	}

	return scope
}

// displayEnd renders an end time, which is absent for assignments that do not
// expire.
func displayEnd(end string) string {
	if end == "" {
		return "permanent"
	}

	return end
}

// reportRequest states what was asked for and whether it took effect.
//
// A request that needs an approver is accepted rather than refused, so saying
// only that it succeeded would imply an access the user does not yet have.
func reportRequest(cmdCtx *Context, name string, duration string, status string) {
	fmt.Fprintf(cmdCtx.ErrOutput, "requested %s for %s (%s)\n", name, duration, status) //nolint:errcheck

	if status == "PendingApproval" {
		fmt.Fprintln(cmdCtx.ErrOutput, "an approver must act on this before the access applies; follow it with the requests command") //nolint:errcheck
	}
}
