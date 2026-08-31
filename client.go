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

func (c *Client) do(ctx context.Context, method string, target string, body []byte, out any) error {
	var reader io.Reader

	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, reader)

	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close() //nolint:errcheck

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return newError(resp.StatusCode, data)
	}

	if out == nil {
		return nil
	}

	return json.Unmarshal(data, out)
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

// newError unwraps a Graph error body.
//
// The PIM endpoints answer with an outer code of "UnknownError" and bury the
// real reason in a JSON document stuffed into the message string. Digging that
// out turns an opaque failure into one naming the scopes that were missing.
func newError(status int, body []byte) error {
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
