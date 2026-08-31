package azpim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/azpim"
)

// eligibleRoles is what the eligibility endpoint answers with in these tests.
// The values are made up; two of the names overlap on purpose, so that an
// ambiguous query can be exercised.
const eligibleRoles = `{"value":[
  {"id":"elig-1","principalId":"user-1","roleDefinitionId":"role-helpdesk",
   "directoryScopeId":"/","memberType":"Direct",
   "roleDefinition":{"displayName":"Helpdesk Administrator"}},
  {"id":"elig-2","principalId":"user-1","roleDefinitionId":"role-user-admin",
   "directoryScopeId":"/","memberType":"Direct",
   "roleDefinition":{"displayName":"User Administrator"}},
  {"id":"elig-3","principalId":"user-1","roleDefinitionId":"role-global-reader",
   "directoryScopeId":"/administrativeUnits/au-1","memberType":"Group",
   "endDateTime":"2027-01-01T00:00:00Z",
   "roleDefinition":{"displayName":"Global Reader"}}
]}`

// graphStub stands in for Graph. Requests land in *captured and *queries so a
// test can inspect what the command sent.
//
// Queries are kept per path because one command can make several calls, and a
// single slot would only ever hold the last of them.
type graphStub struct {
	server   *httptest.Server
	captured map[string]any
	queries  map[string]url.Values
}

func newGraphStub(t *testing.T, routes map[string]string) *graphStub {
	t.Helper()

	stub := &graphStub{queries: map[string]url.Values{}}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.queries[r.URL.Path] = r.URL.Query()

		if r.Method == http.MethodPost {
			body := map[string]any{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			stub.captured = body
		}

		for fragment, response := range routes {
			if strings.Contains(r.URL.Path, fragment) {
				status := http.StatusOK

				// A response written as "<status>|<body>" lets a test drive the
				// error paths.
				if code, rest, found := strings.Cut(response, "|"); found {
					switch code {
					case "403":
						status = http.StatusForbidden
					case "400":
						status = http.StatusBadRequest
					}

					response = rest
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(response))

				return
			}
		}

		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))

	t.Cleanup(stub.server.Close)

	return stub
}

// queryFor returns the query of the request whose path contains fragment.
func (s *graphStub) queryFor(t *testing.T, fragment string) url.Values {
	t.Helper()

	for path, query := range s.queries {
		if strings.Contains(path, fragment) {
			return query
		}
	}

	t.Fatalf("no request was made to a path containing %q", fragment)

	return nil
}

func (s *graphStub) context(out, errOut *bytes.Buffer) *azpim.Context {
	return &azpim.Context{
		Output:    out,
		ErrOutput: errOut,
		Graph: func(_ context.Context, _ []string) (*azpim.Client, error) {
			return &azpim.Client{BaseURL: s.server.URL, Token: "test-token"}, nil
		},
	}
}

func TestRoleListCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{"roleEligibilityScheduleInstances": eligibleRoles})
	out := &bytes.Buffer{}
	cmd := &azpim.RoleListCmd{}

	err := cmd.Run(stub.context(out, &bytes.Buffer{}))

	assert.NoError(err)
	assert.Contains(out.String(), "ROLE")
	assert.Contains(out.String(), "Helpdesk Administrator")
	// The tenant root reads as "tenant" rather than "/".
	assert.Contains(out.String(), "tenant")
	assert.Contains(out.String(), "/administrativeUnits/au-1")
	// An eligibility with no end date is permanent, not blank.
	assert.Contains(out.String(), "permanent")
}

func TestRoleActivateCmd(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		duration string
		status   string
		errMsg   string
		errOut   string
	}{
		{
			name:     "activates",
			role:     "global reader",
			duration: "2h",
			status:   "Provisioned",
			errOut:   "requested Global Reader for PT2H (Provisioned)",
		},
		{
			// An accepted request is not the same as granted access, so a
			// pending one has to say so.
			name:     "pending approval is reported",
			role:     "global reader",
			duration: "2h",
			status:   "PendingApproval",
			errOut:   "an approver must act on this",
		},
		{
			// "Helpdesk Administrator" and "User Administrator" both contain
			// the query. Guessing would activate the wrong role.
			name:     "ambiguous name",
			role:     "administrator",
			duration: "2h",
			errMsg:   "matches more than one",
		},
		{
			name:     "no match",
			role:     "global administrator",
			duration: "2h",
			errMsg:   "no eligible assignment matches",
		},
		{
			name:     "bad duration",
			role:     "global reader",
			duration: "eight hours",
			errMsg:   "invalid duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			stub := newGraphStub(t, map[string]string{
				"roleEligibilityScheduleInstances": eligibleRoles,
				"roleAssignmentScheduleRequests":   `{"id":"req-1","status":"` + tt.status + `"}`,
			})

			errOut := &bytes.Buffer{}
			cmd := &azpim.RoleActivateCmd{
				Role:          tt.role,
				Duration:      tt.duration,
				Justification: "because",
			}

			err := cmd.Run(stub.context(&bytes.Buffer{}, errOut))

			if tt.errMsg != "" {
				assert.ErrorContains(err, tt.errMsg)
				assert.Nil(stub.captured, "nothing should be sent when the request cannot be built")

				return
			}

			assert.NoError(err)
			assert.Contains(errOut.String(), tt.errOut)
		})
	}
}

// TestRoleActivateCmdRequest checks the body, since every identifier in it has
// to come from the matched eligibility rather than be assembled by hand.
func TestRoleActivateCmdRequest(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{
		"roleEligibilityScheduleInstances": eligibleRoles,
		"roleAssignmentScheduleRequests":   `{"id":"req-1","status":"Provisioned"}`,
	})

	cmd := &azpim.RoleActivateCmd{Role: "global reader", Duration: "2h", Justification: "because"}
	err := cmd.Run(stub.context(&bytes.Buffer{}, &bytes.Buffer{}))

	assert.NoError(err)
	require.NotNil(t, stub.captured)
	assert.Equal("selfActivate", stub.captured["action"])
	assert.Equal("user-1", stub.captured["principalId"])
	assert.Equal("role-global-reader", stub.captured["roleDefinitionId"])
	assert.Equal("/administrativeUnits/au-1", stub.captured["directoryScopeId"])
	assert.Equal("because", stub.captured["justification"])

	schedule, ok := stub.captured["scheduleInfo"].(map[string]any)
	require.True(t, ok)
	assert.Equal(map[string]any{"type": "AfterDuration", "duration": "PT2H"}, schedule["expiration"])
	assert.NotEmpty(schedule["startDateTime"])
}

func TestRoleDeactivateCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{
		"roleEligibilityScheduleInstances": eligibleRoles,
		"roleAssignmentScheduleRequests":   `{"id":"req-2","status":"Revoked"}`,
	})

	errOut := &bytes.Buffer{}
	cmd := &azpim.RoleDeactivateCmd{Role: "global reader"}

	err := cmd.Run(stub.context(&bytes.Buffer{}, errOut))

	assert.NoError(err)
	assert.Contains(errOut.String(), "deactivated Global Reader (Revoked)")
	assert.Equal("selfDeactivate", stub.captured["action"])
	// A deactivation has no window, so sending one would be meaningless.
	assert.NotContains(stub.captured, "scheduleInfo")
}

// TestRoleListCmdMissingScopes covers the failure a user actually hits: the PIM
// endpoints bury the reason in a JSON string inside the message field, and an
// error that does not name the missing scopes is not actionable.
func TestRoleListCmdMissingScopes(t *testing.T) {
	assert := assert.New(t)
	body := `{"error":{"code":"UnknownError","message":"{\"errorCode\":\"PermissionScopeNotGranted\",` +
		`\"message\":\"Authorization failed due to missing permission scope RoleEligibilitySchedule.Read.Directory.\"}"}}`
	stub := newGraphStub(t, map[string]string{"roleEligibilityScheduleInstances": "403|" + body})

	cmd := &azpim.RoleListCmd{}
	err := cmd.Run(stub.context(&bytes.Buffer{}, &bytes.Buffer{}))

	assert.ErrorContains(err, "PermissionScopeNotGranted")
	assert.ErrorContains(err, "RoleEligibilitySchedule.Read.Directory")

	var graphErr *azpim.Error
	require.ErrorAs(t, err, &graphErr)
	assert.True(graphErr.MissingScopes())
}

// assignedRoles is what the assignment endpoints answer with. "Activated" is a
// role held through PIM; "Assigned" is a standing one.
const assignedRoles = `{"value":[
  {"id":"asn-1","roleDefinitionId":"role-global-reader","directoryScopeId":"/",
   "assignmentType":"Activated","endDateTime":"2026-01-01T12:00:00Z",
   "roleDefinition":{"displayName":"Global Reader"}},
  {"id":"asn-2","roleDefinitionId":"role-helpdesk","directoryScopeId":"/",
   "assignmentType":"Assigned",
   "roleDefinition":{"displayName":"Helpdesk Administrator"}}
]}`

func TestRoleActiveCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{"roleAssignmentScheduleInstances": assignedRoles})
	out := &bytes.Buffer{}
	cmd := &azpim.RoleActiveCmd{}

	err := cmd.Run(stub.context(out, &bytes.Buffer{}))

	assert.NoError(err)
	assert.Contains(out.String(), "Global Reader")
	assert.Contains(out.String(), "Activated")
	assert.Contains(out.String(), "2026-01-01T12:00:00Z")
	// A standing assignment has no end date.
	assert.Contains(out.String(), "permanent")
}

// TestRoleRequestsCmd also guards the query string. $orderby carries a space,
// which has to be escaped rather than sent raw.
func TestRoleRequestsCmd(t *testing.T) {
	assert := assert.New(t)
	stub := newGraphStub(t, map[string]string{
		"roleAssignmentScheduleRequests": `{"value":[
      {"id":"req-1","createdDateTime":"2026-01-01T00:00:00Z","action":"selfActivate",
       "status":"Provisioned","roleDefinition":{"displayName":"Global Reader"}},
      {"id":"req-2","createdDateTime":"2025-12-31T00:00:00Z","action":"selfDeactivate",
       "status":"Revoked","roleDefinition":{"displayName":"Global Reader"}}
    ]}`,
	})

	out := &bytes.Buffer{}
	cmd := &azpim.RoleRequestsCmd{Limit: 5}

	err := cmd.Run(stub.context(out, &bytes.Buffer{}))

	assert.NoError(err)
	assert.Contains(out.String(), "selfActivate")
	assert.Contains(out.String(), "Provisioned")
	assert.Contains(out.String(), "Revoked")
	query := stub.queryFor(t, "roleAssignmentScheduleRequests")
	assert.Equal("5", query.Get("$top"))
	assert.Equal("createdDateTime desc", query.Get("$orderby"))
}

// TestRoleRequestRejected covers the service refusing a request that was built
// correctly, which is what exceeding the role's policy looks like.
func TestRoleRequestRejected(t *testing.T) {
	rejection := `400|{"error":{"code":"RoleAssignmentRequestPolicyValidationFailed",` +
		`"message":"The duration exceeds the maximum allowed."}}`

	tests := map[string]func(*azpim.Context) error{
		"activate": func(c *azpim.Context) error {
			return (&azpim.RoleActivateCmd{Role: "global reader", Duration: "99h"}).Run(c)
		},
		"deactivate": func(c *azpim.Context) error {
			return (&azpim.RoleDeactivateCmd{Role: "global reader"}).Run(c)
		},
	}

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			stub := newGraphStub(t, map[string]string{
				"roleEligibilityScheduleInstances": eligibleRoles,
				"roleAssignmentScheduleRequests":   rejection,
			})

			err := run(stub.context(&bytes.Buffer{}, &bytes.Buffer{}))

			assert.ErrorContains(err, "RoleAssignmentRequestPolicyValidationFailed")
		})
	}
}
