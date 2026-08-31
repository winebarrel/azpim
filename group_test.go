package azpim_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/azpim"
)

// eligibleGroups gives one group the user may hold as either member or owner,
// which is the case a query naming only the group cannot resolve on its own.
const eligibleGroups = `{"value":[
  {"id":"g-1","groupId":"group-1","principalId":"user-1","accessId":"member"},
  {"id":"g-2","groupId":"group-1","principalId":"user-1","accessId":"owner"},
  {"id":"g-3","groupId":"group-2","principalId":"user-1","accessId":"member",
   "endDateTime":"2027-01-01T00:00:00Z"}
]}`

func groupRoutes(extra map[string]string) map[string]string {
	routes := map[string]string{
		"eligibilityScheduleInstances": eligibleGroups,
		"/groups/group-1":              `{"displayName":"prod-deployers"}`,
		"/groups/group-2":              `{"displayName":"db-admins"}`,
	}

	for key, value := range extra {
		routes[key] = value
	}

	return routes
}

func TestGroupListCmd(t *testing.T) {
	tests := []struct {
		name     string
		access   string
		contains []string
		absent   []string
	}{
		{
			name:     "all access levels",
			access:   "any",
			contains: []string{"prod-deployers", "db-admins", "member", "owner", "permanent"},
		},
		{
			name:     "members only",
			access:   "member",
			contains: []string{"prod-deployers", "db-admins"},
			absent:   []string{"owner"},
		},
		{
			name:     "owners only",
			access:   "owner",
			contains: []string{"prod-deployers"},
			absent:   []string{"db-admins"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			stub := newGraphStub(t, groupRoutes(nil))
			out := &bytes.Buffer{}
			cmd := &azpim.GroupListCmd{AccessFilter: azpim.AccessFilter{Access: tt.access}}

			err := cmd.Run(stub.context(out, &bytes.Buffer{}))

			assert.NoError(err)

			for _, want := range tt.contains {
				assert.Contains(out.String(), want)
			}

			for _, unwanted := range tt.absent {
				assert.NotContains(out.String(), unwanted)
			}
		})
	}
}

// TestGroupListCmdUnnamedGroup covers a directory read that fails: the listing
// is still useful, because the group id identifies the group on its own.
func TestGroupListCmdUnnamedGroup(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{
		"eligibilityScheduleInstances": eligibleGroups,
		"/groups/":                     `403|{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`,
	})

	out := &bytes.Buffer{}
	cmd := &azpim.GroupListCmd{AccessFilter: azpim.AccessFilter{Access: "any"}}

	err := cmd.Run(stub.context(out, &bytes.Buffer{}))

	assert.NoError(err)
	assert.Contains(out.String(), "group-1")
}

func TestGroupActivateCmd(t *testing.T) {
	tests := []struct {
		name   string
		group  string
		access string
		errMsg string
		errOut string
	}{
		{
			name:   "unambiguous group",
			group:  "db-admins",
			access: "any",
			errOut: "requested db-admins [member] for PT2H (Provisioned)",
		},
		{
			// prod-deployers is held twice, once as member and once as owner.
			name:   "member and owner both eligible",
			group:  "prod-deployers",
			access: "any",
			errMsg: "matches more than one",
		},
		{
			name:   "narrowed by access",
			group:  "prod-deployers",
			access: "owner",
			errOut: "requested prod-deployers [owner] for PT2H (Provisioned)",
		},
		{
			name:   "no match",
			group:  "nonexistent",
			access: "any",
			errMsg: "no eligible assignment matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			stub := newGraphStub(t, groupRoutes(map[string]string{
				"assignmentScheduleRequests": `{"id":"req-1","status":"Provisioned"}`,
			}))

			errOut := &bytes.Buffer{}
			cmd := &azpim.GroupActivateCmd{
				AccessFilter:  azpim.AccessFilter{Access: tt.access},
				Group:         tt.group,
				Duration:      "2h",
				Justification: "because",
			}

			err := cmd.Run(stub.context(&bytes.Buffer{}, errOut))

			if tt.errMsg != "" {
				assert.ErrorContains(err, tt.errMsg)
				assert.Nil(stub.captured)

				return
			}

			assert.NoError(err)
			assert.Contains(errOut.String(), tt.errOut)
		})
	}
}

func TestGroupActivateCmdRequest(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, groupRoutes(map[string]string{
		"assignmentScheduleRequests": `{"id":"req-1","status":"Provisioned"}`,
	}))

	cmd := &azpim.GroupActivateCmd{
		AccessFilter:  azpim.AccessFilter{Access: "owner"},
		Group:         "prod-deployers",
		Duration:      "90m",
		Justification: "release",
	}

	err := cmd.Run(stub.context(&bytes.Buffer{}, &bytes.Buffer{}))

	assert.NoError(err)
	require.NotNil(t, stub.captured)
	assert.Equal("selfActivate", stub.captured["action"])
	assert.Equal("group-1", stub.captured["groupId"])
	assert.Equal("user-1", stub.captured["principalId"])
	// The access level comes from the matched eligibility, not from the filter,
	// so a filter of "any" cannot produce a request that names the wrong one.
	assert.Equal("owner", stub.captured["accessId"])
	assert.Equal("release", stub.captured["justification"])

	schedule, ok := stub.captured["scheduleInfo"].(map[string]any)
	require.True(t, ok)
	assert.Equal(map[string]any{"type": "AfterDuration", "duration": "PT1H30M"}, schedule["expiration"])
}

func TestGroupDeactivateCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, groupRoutes(map[string]string{
		"assignmentScheduleRequests": `{"id":"req-2","status":"Revoked"}`,
	}))

	errOut := &bytes.Buffer{}
	cmd := &azpim.GroupDeactivateCmd{
		AccessFilter: azpim.AccessFilter{Access: "member"},
		Group:        "db-admins",
	}

	err := cmd.Run(stub.context(&bytes.Buffer{}, errOut))

	assert.NoError(err)
	assert.Contains(errOut.String(), "deactivated db-admins [member] (Revoked)")
	assert.Equal("selfDeactivate", stub.captured["action"])
	assert.NotContains(stub.captured, "scheduleInfo")
}

// assignedGroups is what the assignment endpoints answer with.
const assignedGroups = `{"value":[
  {"id":"asn-1","groupId":"group-1","principalId":"user-1","accessId":"owner",
   "assignmentType":"Activated","endDateTime":"2026-01-01T12:00:00Z"},
  {"id":"asn-2","groupId":"group-2","principalId":"user-1","accessId":"member",
   "assignmentType":"Assigned"}
]}`

func TestGroupActiveCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{
		"assignmentScheduleInstances": assignedGroups,
		"/groups/group-1":             `{"displayName":"prod-deployers"}`,
		"/groups/group-2":             `{"displayName":"db-admins"}`,
	})

	out := &bytes.Buffer{}
	cmd := &azpim.GroupActiveCmd{AccessFilter: azpim.AccessFilter{Access: "owner"}}

	err := cmd.Run(stub.context(out, &bytes.Buffer{}))

	assert.NoError(err)
	assert.Contains(out.String(), "prod-deployers")
	assert.Contains(out.String(), "Activated")
	// The filter applies here too, so the member row must be gone.
	assert.NotContains(out.String(), "db-admins")
}

func TestGroupRequestsCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{
		"assignmentScheduleRequests": `{"value":[
      {"id":"req-1","groupId":"group-1","accessId":"member",
       "createdDateTime":"2026-01-01T00:00:00Z","action":"selfActivate","status":"PendingApproval"}
    ]}`,
		"/groups/group-1": `{"displayName":"prod-deployers"}`,
	})

	out := &bytes.Buffer{}
	cmd := &azpim.GroupRequestsCmd{Limit: 5}

	err := cmd.Run(stub.context(out, &bytes.Buffer{}))

	assert.NoError(err)
	assert.Contains(out.String(), "prod-deployers")
	assert.Contains(out.String(), "PendingApproval")
	assert.Equal("5", stub.queryFor(t, "assignmentScheduleRequests").Get("$top"))
}
