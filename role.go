package azpim

import (
	"context"
	"fmt"
	"net/url"
)

// RoleScopes are the delegated scopes the role commands sign in for.
//
// RoleManagement.ReadWrite.Directory covers both reading the eligibility
// schedules and writing the assignment requests.
// RoleAssignmentSchedule.ReadWrite.Directory would serve the write side just as
// well, but tenants that have consented to Graph PowerShell at all tend to have
// granted the former.
var RoleScopes = []string{
	"openid",
	"profile",
	"offline_access",
	"RoleEligibilitySchedule.Read.Directory",
	"RoleManagement.ReadWrite.Directory",
}

const rolePath = "/roleManagement/directory"

// RoleCmd groups the Entra ID directory role commands.
type RoleCmd struct {
	List       RoleListCmd       `cmd:"" help:"List the directory roles you are eligible for."`
	Active     RoleActiveCmd     `cmd:"" help:"List the directory roles currently assigned to you."`
	Requests   RoleRequestsCmd   `cmd:"" help:"List your recent activation requests and their approval status."`
	Activate   RoleActivateCmd   `cmd:"" help:"Activate a directory role you are eligible for."`
	Deactivate RoleDeactivateCmd `cmd:"" help:"Deactivate a directory role you have active."`
}

// roleSchedule covers the eligibility, assignment and request resources, which
// differ only in the fields this tool ignores.
type roleSchedule struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	DirectoryScopeID string `json:"directoryScopeId"`
	MemberType       string `json:"memberType"`
	AssignmentType   string `json:"assignmentType"`
	EndDateTime      string `json:"endDateTime"`
	CreatedDateTime  string `json:"createdDateTime"`
	Action           string `json:"action"`
	Status           string `json:"status"`

	RoleDefinition struct {
		DisplayName string `json:"displayName"`
	} `json:"roleDefinition"`
}

func (s roleSchedule) name() string {
	return s.RoleDefinition.DisplayName
}

type roleList struct {
	Value []roleSchedule `json:"value"`
}

// roleRequest is the body of an activation or deactivation request.
type roleRequest struct {
	Action           string        `json:"action"`
	PrincipalID      string        `json:"principalId"`
	RoleDefinitionID string        `json:"roleDefinitionId"`
	DirectoryScopeID string        `json:"directoryScopeId"`
	Justification    string        `json:"justification,omitempty"`
	ScheduleInfo     *scheduleInfo `json:"scheduleInfo,omitempty"`
}

// roleEligibilities reads the roles the signed-in user may activate.
func roleEligibilities(ctx context.Context, client *Client) ([]roleSchedule, error) {
	var result roleList

	err := client.Get(ctx,
		rolePath+"/roleEligibilityScheduleInstances/filterByCurrentUser(on='principal')",
		url.Values{"$expand": {"roleDefinition"}},
		&result)

	return result.Value, err
}

// RoleListCmd lists the roles the signed-in user is eligible for.
type RoleListCmd struct{}

func (cmd *RoleListCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, RoleScopes)

	if err != nil {
		return err
	}

	schedules, err := roleEligibilities(ctx, client)

	if err != nil {
		return err
	}

	rows := [][]string{}

	for _, schedule := range schedules {
		rows = append(rows, []string{
			schedule.name(),
			displayScope(schedule.DirectoryScopeID),
			schedule.MemberType,
			displayEnd(schedule.EndDateTime),
		})
	}

	writeTable(cmdCtx.Output, []string{"ROLE", "SCOPE", "MEMBER TYPE", "EXPIRES"}, rows)

	return nil
}

// RoleActiveCmd lists the roles currently assigned to the signed-in user.
type RoleActiveCmd struct{}

func (cmd *RoleActiveCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, RoleScopes)

	if err != nil {
		return err
	}

	var result roleList

	err = client.Get(ctx,
		rolePath+"/roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')",
		url.Values{"$expand": {"roleDefinition"}},
		&result)

	if err != nil {
		return err
	}

	rows := [][]string{}

	for _, schedule := range result.Value {
		rows = append(rows, []string{
			schedule.name(),
			schedule.AssignmentType,
			displayScope(schedule.DirectoryScopeID),
			displayEnd(schedule.EndDateTime),
		})
	}

	writeTable(cmdCtx.Output, []string{"ROLE", "TYPE", "SCOPE", "ENDS"}, rows)

	return nil
}

// RoleRequestsCmd lists recent activation requests.
//
// It is how an activation that needs approval is followed up: the request is
// accepted immediately but stays pending until an approver acts on it.
type RoleRequestsCmd struct {
	Limit int `default:"20" help:"Number of requests to show."`
}

func (cmd *RoleRequestsCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, RoleScopes)

	if err != nil {
		return err
	}

	var result roleList

	err = client.Get(ctx,
		rolePath+"/roleAssignmentScheduleRequests/filterByCurrentUser(on='principal')",
		url.Values{
			"$expand":  {"roleDefinition"},
			"$top":     {fmt.Sprint(cmd.Limit)},
			"$orderby": {"createdDateTime desc"},
		},
		&result)

	if err != nil {
		return err
	}

	rows := [][]string{}

	for _, schedule := range result.Value {
		rows = append(rows, []string{
			schedule.CreatedDateTime,
			schedule.name(),
			schedule.Action,
			schedule.Status,
		})
	}

	writeTable(cmdCtx.Output, []string{"CREATED", "ROLE", "ACTION", "STATUS"}, rows)

	return nil
}

// RoleActivateCmd activates a role the signed-in user is eligible for.
type RoleActivateCmd struct {
	Role          string `arg:"" help:"Role to activate, matched against the display name."`
	Duration      string `short:"d" default:"8h" help:"How long to hold the role, as a Go duration or ISO 8601."`
	Justification string `short:"j" default:"activated with azpim" help:"Reason recorded with the request."`
}

func (cmd *RoleActivateCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()

	duration, err := parseDuration(cmd.Duration)

	if err != nil {
		return err
	}

	client, err := cmdCtx.Graph(ctx, RoleScopes)

	if err != nil {
		return err
	}

	schedule, err := findRole(ctx, client, cmd.Role)

	if err != nil {
		return err
	}

	// Everything identifying the assignment is copied from the eligibility
	// rather than assembled here, so the request can only ever name a role the
	// user actually holds.
	body := &roleRequest{
		Action:           "selfActivate",
		PrincipalID:      schedule.PrincipalID,
		RoleDefinitionID: schedule.RoleDefinitionID,
		DirectoryScopeID: schedule.DirectoryScopeID,
		Justification:    cmd.Justification,
		ScheduleInfo:     newScheduleInfo(duration),
	}

	var result roleSchedule

	if err := client.Post(ctx, rolePath+"/roleAssignmentScheduleRequests", body, &result); err != nil {
		return err
	}

	reportRequest(cmdCtx, schedule.name(), duration, result.Status)

	return nil
}

// RoleDeactivateCmd gives up a role before it expires.
type RoleDeactivateCmd struct {
	Role string `arg:"" help:"Role to deactivate, matched against the display name."`
}

func (cmd *RoleDeactivateCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, RoleScopes)

	if err != nil {
		return err
	}

	schedule, err := findRole(ctx, client, cmd.Role)

	if err != nil {
		return err
	}

	body := &roleRequest{
		Action:           "selfDeactivate",
		PrincipalID:      schedule.PrincipalID,
		RoleDefinitionID: schedule.RoleDefinitionID,
		DirectoryScopeID: schedule.DirectoryScopeID,
	}

	var result roleSchedule

	if err := client.Post(ctx, rolePath+"/roleAssignmentScheduleRequests", body, &result); err != nil {
		return err
	}

	fmt.Fprintf(cmdCtx.ErrOutput, "deactivated %s (%s)\n", schedule.name(), result.Status) //nolint:errcheck

	return nil
}

// findRole resolves a query against the roles the user is eligible for.
//
// Eligibilities are the source even when deactivating, because they carry the
// same identifiers and a role cannot be active without one.
func findRole(ctx context.Context, client *Client, query string) (roleSchedule, error) {
	schedules, err := roleEligibilities(ctx, client)

	if err != nil {
		return roleSchedule{}, err
	}

	return matchOne(schedules, query, roleSchedule.name)
}
