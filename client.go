package azpim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GraphBaseURL is the Microsoft Graph endpoint commands talk to.
const GraphBaseURL = "https://graph.microsoft.com/v1.0"

// Client is a minimal Microsoft Graph client. Only the handful of calls PIM
// needs are covered, so there is no dependency on a Graph SDK.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client

	// Reauth re-acquires the token so that it carries the claims a challenge
	// asked for. Leaving it nil turns a challenge into a plain error.
	Reauth func(ctx context.Context, claims string) (string, error)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}

	return http.DefaultClient
}

// Get reads path into out. Passing query separately keeps OData parameters
// escaped; $orderby in particular carries a space that must not reach the wire
// raw.
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	target := c.BaseURL + path

	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	return c.do(ctx, http.MethodGet, target, nil, out)
}

// Post sends body to path and decodes the response into out.
func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
	encoded, err := json.Marshal(body)

	if err != nil {
		return err
	}

	return c.do(ctx, http.MethodPost, c.BaseURL+path, encoded, out)
}

// do makes the call and, if it comes back as a claims challenge, signs in
// again and makes it once more.
//
// The retry lives here rather than in the commands because any PIM call can be
// challenged, and because the second attempt has to be identical to the first:
// re-deriving the request would risk sending something subtly different than
// what was refused.
func (c *Client) do(ctx context.Context, method string, target string, body []byte, out any) error {
	status, data, err := c.send(ctx, method, target, body)

	if err != nil {
		return err
	}

	if status >= http.StatusBadRequest {
		failure := newError(status, data)
		claims := failure.ClaimsChallenge()

		if claims == "" || c.Reauth == nil {
			return failure
		}

		token, err := c.Reauth(ctx, claims)

		if err != nil {
			return err
		}

		c.Token = token

		if status, data, err = c.send(ctx, method, target, body); err != nil {
			return err
		}

		// A challenge answered with a token that is still refused is reported
		// as it came back, so a policy this tool cannot satisfy is not
		// disguised as the original failure.
		if status >= http.StatusBadRequest {
			return newError(status, data)
		}
	}

	if out == nil {
		return nil
	}

	return json.Unmarshal(data, out)
}

// send makes one request and reads its reply, leaving the status for do to act
// on.
func (c *Client) send(ctx context.Context, method string, target string, body []byte) (int, []byte, error) {
	var reader io.Reader

	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, reader)

	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)

	if err != nil {
		return 0, nil, err
	}

	defer resp.Body.Close() //nolint:errcheck

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, data, nil
}

// Error is a failed Graph call.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("graph request failed with status %d: %s: %s", e.Status, e.Code, e.Message)
}

// MissingScopes reports whether the call failed because the token lacks the
// required consent, which is the failure worth telling a user how to fix.
func (e *Error) MissingScopes() bool {
	return e.Code == "PermissionScopeNotGranted" || e.Status == http.StatusForbidden
}

// ClaimsChallenge returns the claims the call is asking to be re-issued with,
// or an empty string when the failure was not a challenge.
//
// Conditional Access can put an authentication context on a role, and PIM
// refuses an activation whose token has not satisfied it. The refusal carries
// the challenge as a URL-encoded query fragment glued onto the message
// ("&claims=%7B%22access_token%22...") rather than in the header the protocol
// puts it in, so it has to be dug out of the prose. Signing in again with
// those claims is what satisfies the context.
func (e *Error) ClaimsChallenge() string {
	_, rest, found := strings.Cut(e.Message, "claims=")

	if !found {
		return ""
	}

	// The fragment runs to the end of the message unless more prose follows it.
	if end := strings.IndexAny(rest, " \t\r\n\"&"); end >= 0 {
		rest = rest[:end]
	}

	decoded, err := url.QueryUnescape(rest)

	// Anything that does not decode to a claims document is a message that
	// merely mentions the word, and answering it with a sign-in would be a
	// browser opened for no reason.
	if err != nil || !json.Valid([]byte(decoded)) {
		return ""
	}

	return decoded
}

// newError unwraps a Graph error body.
//
// The PIM endpoints answer with an outer code of "UnknownError" and bury the
// real reason in a JSON document stuffed into the message string. Digging that
// out turns an opaque failure into one naming the scopes that were missing.
func newError(status int, body []byte) *Error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &envelope); err != nil {
		return &Error{Status: status, Code: "unknown", Message: strings.TrimSpace(string(body))}
	}

	result := &Error{
		Status:  status,
		Code:    envelope.Error.Code,
		Message: envelope.Error.Message,
	}

	var inner struct {
		ErrorCode string `json:"errorCode"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal([]byte(envelope.Error.Message), &inner); err == nil && inner.ErrorCode != "" {
		result.Code = inner.ErrorCode
		result.Message = inner.Message
	}

	return result
}
