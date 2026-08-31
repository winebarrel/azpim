package azpim

import (
	"context"
	"fmt"
	"net/url"
)

// GroupScopes are the delegated scopes the group commands sign in for.
//
// These are distinct from the AzureAD scopes the role commands use: consenting
// to PrivilegedAccess.ReadWrite.AzureAD grants nothing over groups, despite the
// names being a character apart. Directory.Read.All is here only to turn group
// ids into names.
var GroupScopes = []string{
	"openid",
	"profile",
	"offline_access",
	"PrivilegedEligibilitySchedule.Read.AzureADGroup",
	"PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
	"Directory.Read.All",
}

const groupPath = "/identityGovernance/privilegedAccess/group"

// GroupCmd groups the PIM for Groups commands.
type GroupCmd struct {
	List       GroupListCmd       `cmd:"" help:"List the group memberships you are eligible for."`
	Active     GroupActiveCmd     `cmd:"" help:"List the group memberships currently assigned to you."`
	Requests   GroupRequestsCmd   `cmd:"" help:"List your recent activation requests and their approval status."`
	Activate   GroupActivateCmd   `cmd:"" help:"Activate a group membership you are eligible for."`
	Deactivate GroupDeactivateCmd `cmd:"" help:"Deactivate a group membership you have active."`
}

// groupSchedule covers the eligibility, assignment and request resources.
type groupSchedule struct {
	ID              string `json:"id"`
	GroupID         string `json:"groupId"`
	PrincipalID     string `json:"principalId"`
	AccessID        string `json:"accessId"`
	AssignmentType  string `json:"assignmentType"`
	EndDateTime     string `json:"endDateTime"`
	CreatedDateTime string `json:"createdDateTime"`
	Action          string `json:"action"`
	Status          string `json:"status"`

	// displayName is resolved separately: these resources carry only the group
	// id, which is no use for matching a name typed on the command line.
	displayName string
}

func (s groupSchedule) name() string {
	if s.displayName == "" {
		return s.GroupID
	}

	return s.displayName
}

type groupList struct {
	Value []groupSchedule `json:"value"`
}

// groupRequest is the body of an activation or deactivation request.
type groupRequest struct {
	Action        string        `json:"action"`
	GroupID       string        `json:"groupId"`
	PrincipalID   string        `json:"principalId"`
	AccessID      string        `json:"accessId"`
	Justification string        `json:"justification,omitempty"`
	ScheduleInfo  *scheduleInfo `json:"scheduleInfo,omitempty"`
}

// AccessFilter narrows a listing to member or owner assignments.
//
// Being eligible for both on the same group is normal, and the two are
// different grants, so a command naming only the group would otherwise be
// ambiguous.
type AccessFilter struct {
	Access string `enum:"any,member,owner" default:"any" help:"Limit to member or owner assignments."`
}

func (f AccessFilter) apply(schedules []groupSchedule) []groupSchedule {
	if f.Access == "any" {
		return schedules
	}

	kept := []groupSchedule{}

	for _, schedule := range schedules {
		if schedule.AccessID == f.Access {
			kept = append(kept, schedule)
		}
	}

	return kept
}

// listGroupSchedules reads a group resource and fills in the display names.
func listGroupSchedules(ctx context.Context, client *Client, path string, query url.Values) ([]groupSchedule, error) {
	var result groupList

	if err := client.Get(ctx, groupPath+path, query, &result); err != nil {
		return nil, err
	}

	names := map[string]string{}

	for i, schedule := range result.Value {
		if _, ok := names[schedule.GroupID]; !ok {
			names[schedule.GroupID] = groupName(ctx, client, schedule.GroupID)
		}

		result.Value[i].displayName = names[schedule.GroupID]
	}

	return result.Value, nil
}

// groupName resolves a group id to its display name, falling back to the id.
//
// A name is a convenience, so failing to read one is not worth failing the
// whole listing over: the id still identifies the group.
func groupName(ctx context.Context, client *Client, id string) string {
	var group struct {
		DisplayName string `json:"displayName"`
	}

	if err := client.Get(ctx, "/groups/"+id, url.Values{"$select": {"displayName"}}, &group); err != nil {
		return ""
	}

	return group.DisplayName
}

func groupEligibilities(ctx context.Context, client *Client) ([]groupSchedule, error) {
	return listGroupSchedules(ctx, client, "/eligibilityScheduleInstances/filterByCurrentUser(on='principal')", nil)
}

// GroupListCmd lists the group memberships the signed-in user is eligible for.
type GroupListCmd struct {
	AccessFilter
}

func (cmd *GroupListCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, GroupScopes)

	if err != nil {
		return err
	}

	schedules, err := groupEligibilities(ctx, client)

	if err != nil {
		return err
	}

	rows := [][]string{}

	for _, schedule := range cmd.apply(schedules) {
		rows = append(rows, []string{
			schedule.name(),
			schedule.AccessID,
			schedule.GroupID,
			displayEnd(schedule.EndDateTime),
		})
	}

	writeTable(cmdCtx.Output, []string{"GROUP", "ACCESS", "GROUP ID", "EXPIRES"}, rows)

	return nil
}

// GroupActiveCmd lists the group memberships currently assigned.
type GroupActiveCmd struct {
	AccessFilter
}

func (cmd *GroupActiveCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, GroupScopes)

	if err != nil {
		return err
	}

	schedules, err := listGroupSchedules(ctx, client,
		"/assignmentScheduleInstances/filterByCurrentUser(on='principal')", nil)

	if err != nil {
		return err
	}

	rows := [][]string{}

	for _, schedule := range cmd.apply(schedules) {
		rows = append(rows, []string{
			schedule.name(),
			schedule.AccessID,
			schedule.AssignmentType,
			displayEnd(schedule.EndDateTime),
		})
	}

	writeTable(cmdCtx.Output, []string{"GROUP", "ACCESS", "TYPE", "ENDS"}, rows)

	return nil
}

// GroupRequestsCmd lists recent activation requests.
type GroupRequestsCmd struct {
	Limit int `default:"20" help:"Number of requests to show."`
}

func (cmd *GroupRequestsCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, GroupScopes)

	if err != nil {
		return err
	}

	schedules, err := listGroupSchedules(ctx, client,
		"/assignmentScheduleRequests/filterByCurrentUser(on='principal')",
		url.Values{"$top": {fmt.Sprint(cmd.Limit)}})

	if err != nil {
		return err
	}

	rows := [][]string{}

	for _, schedule := range schedules {
		rows = append(rows, []string{
			schedule.CreatedDateTime,
			schedule.name(),
			schedule.AccessID,
			schedule.Action,
			schedule.Status,
		})
	}

	writeTable(cmdCtx.Output, []string{"CREATED", "GROUP", "ACCESS", "ACTION", "STATUS"}, rows)

	return nil
}

// GroupActivateCmd activates a group membership.
type GroupActivateCmd struct {
	AccessFilter

	Group         string `arg:"" help:"Group to activate, matched against the display name."`
	Duration      string `short:"d" default:"8h" help:"How long to hold the membership, as a Go duration or ISO 8601."`
	Justification string `short:"j" default:"activated with azpim" help:"Reason recorded with the request."`
}

func (cmd *GroupActivateCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()

	duration, err := parseDuration(cmd.Duration)

	if err != nil {
		return err
	}

	client, err := cmdCtx.Graph(ctx, GroupScopes)

	if err != nil {
		return err
	}

	schedule, err := findGroup(ctx, client, cmd.Group, cmd.AccessFilter)

	if err != nil {
		return err
	}

	body := &groupRequest{
		Action:        "selfActivate",
		GroupID:       schedule.GroupID,
		PrincipalID:   schedule.PrincipalID,
		AccessID:      schedule.AccessID,
		Justification: cmd.Justification,
		ScheduleInfo:  newScheduleInfo(duration),
	}

	var result groupSchedule

	if err := client.Post(ctx, groupPath+"/assignmentScheduleRequests", body, &result); err != nil {
		return err
	}

	label := fmt.Sprintf("%s [%s]", schedule.name(), schedule.AccessID)

	reportRequest(cmdCtx, label, duration, result.Status)

	return nil
}

// GroupDeactivateCmd gives up a group membership before it expires.
type GroupDeactivateCmd struct {
	AccessFilter

	Group string `arg:"" help:"Group to deactivate, matched against the display name."`
}

func (cmd *GroupDeactivateCmd) Run(cmdCtx *Context) error {
	ctx := context.Background()
	client, err := cmdCtx.Graph(ctx, GroupScopes)

	if err != nil {
		return err
	}

	schedule, err := findGroup(ctx, client, cmd.Group, cmd.AccessFilter)

	if err != nil {
		return err
	}

	body := &groupRequest{
		Action:      "selfDeactivate",
		GroupID:     schedule.GroupID,
		PrincipalID: schedule.PrincipalID,
		AccessID:    schedule.AccessID,
	}

	var result groupSchedule

	if err := client.Post(ctx, groupPath+"/assignmentScheduleRequests", body, &result); err != nil {
		return err
	}

	fmt.Fprintf(cmdCtx.ErrOutput, "deactivated %s [%s] (%s)\n", schedule.name(), schedule.AccessID, result.Status) //nolint:errcheck

	return nil
}

// findGroup resolves a query against the memberships the user is eligible for.
func findGroup(ctx context.Context, client *Client, query string, filter AccessFilter) (groupSchedule, error) {
	schedules, err := groupEligibilities(ctx, client)

	if err != nil {
		return groupSchedule{}, err
	}

	return matchOne(filter.apply(schedules), query, groupSchedule.name)
}
