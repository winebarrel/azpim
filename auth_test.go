package azpim_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/azpim"
)

// tokenStub stands in for the identity platform's token endpoint.
type tokenStub struct {
	server *httptest.Server
	form   url.Values
	reply  string
}

func newTokenStub(t *testing.T, reply string) *tokenStub {
	t.Helper()

	stub := &tokenStub{reply: reply}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		stub.form, err = url.ParseQuery(string(body))
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(stub.reply))
	}))

	t.Cleanup(stub.server.Close)

	return stub
}

// browser plays the part of the identity platform redirecting back, so the
// whole flow can be exercised without one.
//
// It returns the challenge it saw, letting a test confirm that the verifier
// later sent to the token endpoint is the one it was derived from.
func browser(t *testing.T, challenge *string, tamper func(url.Values)) func(string) error {
	t.Helper()

	return func(target string) error {
		parsed, err := url.Parse(target)
		require.NoError(t, err)

		query := parsed.Query()
		*challenge = query.Get("code_challenge")
		require.Equal(t, "S256", query.Get("code_challenge_method"))

		redirect := query.Get("redirect_uri")
		require.NotEmpty(t, redirect)

		back := url.Values{"code": {"auth-code"}, "state": {query.Get("state")}}

		if tamper != nil {
			tamper(back)
		}

		resp, err := http.Get(redirect + "?" + back.Encode()) //nolint:noctx
		require.NoError(t, err)

		return resp.Body.Close()
	}
}

func writeCachedToken(t *testing.T, dir string, token map[string]any) {
	t.Helper()

	require.NoError(t, os.MkdirAll(dir, 0o700))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	// The cache file name embeds a digest of the scopes, which is not something
	// a test should reproduce. Sign in once to create the file, then rewrite it.
	require.NotEmpty(t, entries, "expected a cache file to already exist")

	data, err := json.Marshal(token)
	require.NoError(t, err)

	for _, entry := range entries {
		require.NoError(t, os.WriteFile(filepath.Join(dir, entry.Name()), data, 0o600))
	}

}

func TestAuthenticatorSignIn(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	errOut := &bytes.Buffer{}
	auth := &azpim.Authenticator{
		TenantID:  "tenant-1",
		ClientID:  "client-1",
		Endpoint:  stub.server.URL,
		CacheDir:  t.TempDir(),
		ErrOutput: errOut,
		Browser:   browser(t, &challenge, nil),
	}

	token, err := auth.Token(context.Background(), []string{"openid", "Scope.One"})

	assert.NoError(err)
	assert.Equal("access-1", token)
	assert.Equal("authorization_code", stub.form.Get("grant_type"))
	assert.Equal("auth-code", stub.form.Get("code"))
	assert.Equal("openid Scope.One", stub.form.Get("scope"))
	// No secret is held by a public client; PKCE is what proves the redemption
	// belongs to the request that started the flow.
	assert.Empty(stub.form.Get("client_secret"))

	verifier := stub.form.Get("code_verifier")
	assert.NotEmpty(verifier)

	sum := sha256.Sum256([]byte(verifier))
	assert.Equal(challenge, base64.RawURLEncoding.EncodeToString(sum[:]))

	// The sign-in URL is printed so a browser that refuses to open is not a
	// dead end.
	assert.Contains(errOut.String(), stub.server.URL)
}

// TestAuthenticatorSignInStateMismatch covers a redirect that does not belong
// to this flow. The code it carries must not be redeemed.
func TestAuthenticatorSignInStateMismatch(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","expires_in":3600}`)

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		Browser: browser(t, &challenge, func(back url.Values) {
			back.Set("state", "not-the-state-we-sent")
		}),
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.ErrorContains(err, "did not match the request")
	assert.Nil(stub.form, "the code must not be redeemed")
}

func TestAuthenticatorSignInError(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"unused"}`)

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		Browser: browser(t, &challenge, func(back url.Values) {
			back.Del("code")
			back.Set("error", "access_denied")
			back.Set("error_description", "blocked by a conditional access policy")
		}),
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.ErrorContains(err, "access_denied")
	assert.ErrorContains(err, "conditional access")
}

func TestAuthenticatorReusesCachedToken(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := t.TempDir()
	scopes := []string{"openid", "Scope.One"}
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), scopes)
	require.NoError(t, err)

	// A second call must not sign in again.
	auth.Browser = func(string) error {
		t.Error("a cached token should not trigger a sign-in")

		return nil
	}

	token, err := auth.Token(context.Background(), scopes)

	assert.NoError(err)
	assert.Equal("access-1", token)
}

// TestAuthenticatorRefreshes covers an expired access token: the refresh token
// renews it without putting a browser in the way.
func TestAuthenticatorRefreshes(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := t.TempDir()
	scopes := []string{"openid", "Scope.One"}
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), scopes)
	require.NoError(t, err)

	writeCachedToken(t, dir, map[string]any{
		"access_token":  "stale",
		"refresh_token": "refresh-1",
		"expires_at":    time.Now().Add(-time.Hour).Unix(),
	})

	stub.reply = `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`
	auth.Browser = func(string) error {
		t.Error("an expired token should be refreshed, not re-authorized")

		return nil
	}

	token, err := auth.Token(context.Background(), scopes)

	assert.NoError(err)
	assert.Equal("access-2", token)
	assert.Equal("refresh_token", stub.form.Get("grant_type"))
	assert.Equal("refresh-1", stub.form.Get("refresh_token"))
}

// TestAuthenticatorScopesKeyTheCache covers asking for a different area: a
// token issued for one scope set would be rejected by Graph for another, so it
// must not be reused.
func TestAuthenticatorScopesKeyTheCache(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	signIns := 0
	dir := t.TempDir()
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
	}

	auth.Browser = func(target string) error {
		signIns++

		return browser(t, &challenge, nil)(target)
	}

	_, err := auth.Token(context.Background(), azpim.RoleScopes)
	require.NoError(t, err)

	_, err = auth.Token(context.Background(), azpim.GroupScopes)
	require.NoError(t, err)

	assert.Equal(2, signIns)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(entries, 2, "each scope set gets its own cache entry")
}

func TestAuthenticatorCachePermissions(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := filepath.Join(t.TempDir(), "cache")
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), []string{"openid"})
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// A refresh token is a long-lived credential and has no business being
	// readable by anyone else on the machine.
	info, err := os.Stat(filepath.Join(dir, entries[0].Name()))
	require.NoError(t, err)
	assert.Equal(os.FileMode(0o600), info.Mode().Perm(), fmt.Sprintf("mode was %s", info.Mode()))
}

// TestAuthenticatorClient checks the wiring between a fresh token and the Graph
// client the commands are handed.
func TestAuthenticatorClient(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		Browser:  browser(t, &challenge, nil),
	}

	client, err := auth.Client(context.Background(), []string{"openid"})

	require.NoError(t, err)
	assert.Equal(azpim.GraphBaseURL, client.BaseURL)
	assert.Equal("access-1", client.Token)
}

// TestAuthenticatorClientSignInFails covers a sign-in that does not complete:
// no client comes back, so a command cannot proceed with a nil token.
func TestAuthenticatorClientSignInFails(t *testing.T) {
	assert := assert.New(t)

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "",
		CacheDir: t.TempDir(),
	}

	client, err := auth.Client(context.Background(), []string{"openid"})

	assert.ErrorContains(err, "client id")
	assert.Nil(client)
}
