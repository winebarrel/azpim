package azpim_test

import (
	"context"
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
