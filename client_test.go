package azpim_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/azpim"
)

func TestClientUnreachable(t *testing.T) {
	assert := assert.New(t)

	// A server that is closed before use gives an address nothing answers on.
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	client := &azpim.Client{BaseURL: url, Token: "test-token"}
	err := client.Get(context.Background(), "/anything", nil, &struct{}{})

	assert.Error(err)
}

func TestClientBadURL(t *testing.T) {
	assert := assert.New(t)

	// A control character cannot appear in a URL, so the request never forms.
	client := &azpim.Client{BaseURL: "http://\x7f", Token: "test-token"}
	err := client.Get(context.Background(), "/anything", nil, &struct{}{})

	assert.Error(err)
}

// TestClientErrorNotJSON covers a failure body that is not the shape Graph
// documents, such as one written by a proxy in front of it.
func TestClientErrorNotJSON(t *testing.T) {
	assert := assert.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{BaseURL: server.URL, Token: "test-token"}
	err := client.Get(context.Background(), "/anything", nil, &struct{}{})

	var graphErr *azpim.Error
	require.ErrorAs(t, err, &graphErr)
	assert.Equal(http.StatusBadGateway, graphErr.Status)
	assert.Equal("unknown", graphErr.Code)
	assert.Contains(graphErr.Message, "502 Bad Gateway")
	// Anything past 400 is worth pointing at consent, even when the body gives
	// no code to go on.
	assert.False(graphErr.MissingScopes())
}

// TestClientErrorWithoutInnerCode covers an ordinary Graph error, where the
// message is prose rather than another JSON document.
func TestClientErrorWithoutInnerCode(t *testing.T) {
	assert := assert.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{BaseURL: server.URL, Token: "test-token"}
	err := client.Get(context.Background(), "/anything", nil, &struct{}{})

	var graphErr *azpim.Error
	require.ErrorAs(t, err, &graphErr)
	assert.Equal("Request_ResourceNotFound", graphErr.Code)
	assert.Equal("not found", graphErr.Message)
	assert.Contains(err.Error(), "status 404")
}

// TestClientUsesSuppliedHTTPClient covers a caller providing its own transport.
func TestClientUsesSuppliedHTTPClient(t *testing.T) {
	assert := assert.New(t)

	seen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization") == "Bearer test-token"
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{BaseURL: server.URL, Token: "test-token", HTTP: server.Client()}
	err := client.Get(context.Background(), "/anything", nil, &struct{}{})

	assert.NoError(err)
	assert.True(seen, "the token is sent as a bearer credential")
}

// TestClientPostWithoutResult covers a response body that is not decoded,
// which is how a request is sent when only its acceptance matters.
func TestClientPostWithoutResult(t *testing.T) {
	assert := assert.New(t)

	var contentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{BaseURL: server.URL, Token: "test-token"}
	err := client.Post(context.Background(), "/anything", map[string]string{"a": "b"}, nil)

	assert.NoError(err)
	assert.Equal("application/json", contentType)
}

// acrsBody is the refusal PIM sends when a role sits behind a Conditional
// Access authentication context: an outer "UnknownError" wrapping a document
// whose message is the claims challenge as a bare query fragment.
const acrsBody = `{"error":{"code":"UnknownError","message":"{\"errorCode\":\"RoleAssignmentRequestAcrsValidationFailed\",\"message\":\"&claims=%7B%22access_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%20%22value%22%3A%22c1%22%7D%7D%7D\"}"}}`

// wantedClaims is what that fragment decodes to.
const wantedClaims = `{"access_token":{"acrs":{"essential":true, "value":"c1"}}}`

// TestClientClaimsChallengeRetried covers an activation refused for want of an
// authentication context: the token is re-acquired against the challenge and
// the request is sent again as it was.
func TestClientClaimsChallengeRetried(t *testing.T) {
	assert := assert.New(t)

	tokens := []string{}
	bodies := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		tokens = append(tokens, r.Header.Get("Authorization"))
		bodies = append(bodies, string(body))

		if len(tokens) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(acrsBody))

			return
		}

		_, _ = w.Write([]byte(`{"status":"Provisioned"}`))
	}))
	t.Cleanup(server.Close)

	var asked string

	client := &azpim.Client{
		BaseURL: server.URL,
		Token:   "plain-token",
		Reauth: func(_ context.Context, claims string) (string, error) {
			asked = claims

			return "acrs-token", nil
		},
	}

	var result struct {
		Status string `json:"status"`
	}

	err := client.Post(context.Background(), "/requests", map[string]string{"action": "selfActivate"}, &result)

	assert.NoError(err)
	assert.Equal("Provisioned", result.Status)
	// The challenge is handed on as the tenant wrote it, decoded but not
	// rebuilt.
	assert.Equal(wantedClaims, asked)
	assert.Equal([]string{"Bearer plain-token", "Bearer acrs-token"}, tokens)
	assert.Equal(bodies[0], bodies[1], "the retry sends the request that was refused")
}

// TestClientClaimsChallengeWithoutReauth covers a client that has no way to
// answer a challenge, which must surface the refusal rather than swallow it.
func TestClientClaimsChallengeWithoutReauth(t *testing.T) {
	assert := assert.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(acrsBody))
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{BaseURL: server.URL, Token: "plain-token"}
	err := client.Post(context.Background(), "/requests", map[string]string{}, nil)

	var graphErr *azpim.Error
	require.ErrorAs(t, err, &graphErr)
	assert.Equal("RoleAssignmentRequestAcrsValidationFailed", graphErr.Code)
	assert.Equal(wantedClaims, graphErr.ClaimsChallenge())
}

// TestClientClaimsChallengeStillRefused covers a context this tool cannot
// satisfy, such as one demanding a compliant device. The second refusal is
// what the user is shown.
func TestClientClaimsChallengeStillRefused(t *testing.T) {
	assert := assert.New(t)

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++

		w.WriteHeader(http.StatusBadRequest)

		if calls == 1 {
			_, _ = w.Write([]byte(acrsBody))

			return
		}

		_, _ = w.Write([]byte(`{"error":{"code":"AccessDenied","message":"still not satisfied"}}`))
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{
		BaseURL: server.URL,
		Token:   "plain-token",
		Reauth: func(context.Context, string) (string, error) {
			return "acrs-token", nil
		},
	}

	err := client.Post(context.Background(), "/requests", map[string]string{}, nil)

	var graphErr *azpim.Error
	require.ErrorAs(t, err, &graphErr)
	assert.Equal("AccessDenied", graphErr.Code)
	// Two attempts, and no third: a challenge is answered once.
	assert.Equal(2, calls)
}

// TestClientClaimsChallengeSignInFails covers a sign-in the user abandons.
func TestClientClaimsChallengeSignInFails(t *testing.T) {
	assert := assert.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(acrsBody))
	}))
	t.Cleanup(server.Close)

	client := &azpim.Client{
		BaseURL: server.URL,
		Token:   "plain-token",
		Reauth: func(context.Context, string) (string, error) {
			return "", errors.New("timed out waiting for the sign-in to complete")
		},
	}

	err := client.Post(context.Background(), "/requests", map[string]string{}, nil)

	assert.ErrorContains(err, "timed out waiting")
}

// TestClientErrorMentioningClaims covers a message that merely contains the
// word. Opening a browser for it would be a prompt with nothing behind it.
func TestClientErrorMentioningClaims(t *testing.T) {
	assert := assert.New(t)

	graphErr := &azpim.Error{Status: 400, Code: "BadRequest", Message: "the claims=abc parameter was not understood"}

	assert.Empty(graphErr.ClaimsChallenge())
	assert.Empty((&azpim.Error{Message: "no challenge here"}).ClaimsChallenge())
}

// abortingServer answers once as told and then drops the connection, which is
// how a transport failure is provoked without an unroutable address.
func abortingServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, calls int)) *httptest.Server {
	t.Helper()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++

		handler(w, r, calls)
	}))

	// An aborted handler is the point of this server, not a fault to report.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)

	t.Cleanup(server.Close)

	return server
}

// TestClientClaimsChallengeRetryUnreachable covers the retry itself failing to
// reach Graph, which is a transport error and not a refusal to dress up as one.
func TestClientClaimsChallengeRetryUnreachable(t *testing.T) {
	assert := assert.New(t)

	server := abortingServer(t, func(w http.ResponseWriter, _ *http.Request, calls int) {
		if calls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(acrsBody))

			return
		}

		panic(http.ErrAbortHandler)
	})

	client := &azpim.Client{
		BaseURL: server.URL,
		Token:   "plain-token",
		Reauth: func(context.Context, string) (string, error) {
			return "acrs-token", nil
		},
	}

	err := client.Post(context.Background(), "/requests", map[string]string{}, nil)

	assert.Error(err)

	var graphErr *azpim.Error
	assert.NotErrorAs(err, &graphErr, "a connection that died is not an answer from Graph")
}

// TestClientResponseBodyTruncated covers a reply that stops partway through,
// which must not be decoded as though it had arrived whole.
func TestClientResponseBodyTruncated(t *testing.T) {
	assert := assert.New(t)

	server := abortingServer(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		// A length longer than what follows leaves the read waiting for bytes
		// the aborted connection never delivers. The flush is what puts the
		// head on the wire, so the failure lands on the body rather than on
		// the request.
		w.Header().Set("Content-Length", "128")
		_, _ = w.Write([]byte(`{"status":"Prov`))
		w.(http.Flusher).Flush()

		panic(http.ErrAbortHandler)
	})

	client := &azpim.Client{BaseURL: server.URL, Token: "test-token"}

	var result struct {
		Status string `json:"status"`
	}

	err := client.Get(context.Background(), "/anything", nil, &result)

	assert.Error(err)
	assert.Empty(result.Status)
}
