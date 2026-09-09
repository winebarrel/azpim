package azpim_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/azpim"
)

// tokenStub stands in for the identity platform's token endpoint.
//
// replies keyed by grant type let one stub answer a refresh differently from a
// code redemption, which is what a rejected refresh token looks like.
type tokenStub struct {
	server  *httptest.Server
	form    url.Values
	reply   string
	replies map[string]string
}

func newTokenStub(t *testing.T, reply string) *tokenStub {
	t.Helper()

	stub := &tokenStub{reply: reply}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		stub.form, err = url.ParseQuery(string(body))
		require.NoError(t, err)

		reply := stub.reply

		if specific, ok := stub.replies[stub.form.Get("grant_type")]; ok {
			reply = specific
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
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

// accessEntries names the cache files holding an access token.
//
// The refresh token has an entry of its own, shared by every scope set and
// every area, so counting what was filed for a token means leaving it out.
func accessEntries(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var names []string

	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)

		var token struct {
			AccessToken string `json:"access_token"`
		}

		require.NoError(t, json.Unmarshal(data, &token))

		if token.AccessToken != "" {
			names = append(names, entry.Name())
		}
	}

	return names
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
//
// Getting a token of its own for the second area is not the same as signing in
// again for it, and only the first of those is acceptable in a command line
// tool. The refresh token from the first sign-in is what the second area
// redeems, so the browser opens once.
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

	assert.Equal(1, signIns, "the second area redeems the refresh token instead of signing in")
	assert.Equal("refresh_token", stub.form.Get("grant_type"))
	assert.Equal(strings.Join(azpim.GroupScopes, " "), stub.form.Get("scope"))

	assert.Len(accessEntries(t, dir), 2, "each scope set gets its own cache entry")
}

// TestAuthenticatorUnconsentedAreaSignsInAgain covers the other half of sharing
// one refresh token between areas. An area the tenant has not consented to is
// refused at the token endpoint, and that has to become a sign-in for that
// area rather than a failure: signing in once is the point, but not at the cost
// of an area no longer being reachable on its own.
func TestAuthenticatorUnconsentedAreaSignsInAgain(t *testing.T) {
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
	require.Equal(t, 1, signIns)

	// Redeeming the refresh token for scopes the application has not been
	// granted is refused, which is what the second area looks like in a tenant
	// that consented only to the first.
	stub.replies = map[string]string{
		"refresh_token":      `{"error":"invalid_grant","error_description":"AADSTS65001: no consent"}`,
		"authorization_code": `{"access_token":"access-group","refresh_token":"refresh-2","expires_in":3600}`,
	}

	token, err := auth.Token(context.Background(), azpim.GroupScopes)

	assert.NoError(err)
	assert.Equal("access-group", token)
	assert.Equal(2, signIns, "the refused area falls back to a sign-in of its own")
}

// TestAuthenticatorClientIDKeysTheCache covers switching --client-id with the
// tenant and scopes left alone, which is what moving off the default
// application looks like. A token belongs to the application it was issued to,
// so reusing the previous one would keep signing in through the very
// application the switch is meant to stop using.
func TestAuthenticatorClientIDKeysTheCache(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	signIns := 0
	dir := t.TempDir()
	scopes := []string{"openid", "Scope.One"}

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

	_, err := auth.Token(context.Background(), scopes)
	require.NoError(t, err)
	assert.Equal("client-1", stub.form.Get("client_id"))

	auth.ClientID = "client-2"

	_, err = auth.Token(context.Background(), scopes)
	require.NoError(t, err)

	assert.Equal(2, signIns)
	// The second token was redeemed for the new application rather than read
	// back from the first one's cache entry, and the first one's refresh token
	// was not silently reused to get it either.
	assert.Equal("client-2", stub.form.Get("client_id"))
	assert.Equal("authorization_code", stub.form.Get("grant_type"))

	assert.Len(accessEntries(t, dir), 2, "each application gets its own cache entry")
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
	require.NotEmpty(t, entries)

	// A refresh token is a long-lived credential and has no business being
	// readable by anyone else on the machine. It has an entry of its own, so
	// every entry is checked rather than the one an access token went into.
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		assert.Equal(os.FileMode(0o600), info.Mode().Perm(), fmt.Sprintf("%s was %s", entry.Name(), info.Mode()))
	}
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

func TestAuthenticatorTokenEndpointRejects(t *testing.T) {
	tests := map[string]struct {
		reply  string
		errMsg string
	}{
		"named error": {
			reply:  `{"error":"invalid_grant","error_description":"the code has expired"}`,
			errMsg: "invalid_grant: the code has expired",
		},
		// A 200 with nothing usable in it must not be mistaken for success.
		"no token in the response": {
			reply:  `{"token_type":"Bearer"}`,
			errMsg: "no access token",
		},
		"not json at all": {
			reply:  `<html>gateway error</html>`,
			errMsg: "invalid character",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			stub := newTokenStub(t, tt.reply)

			var challenge string

			auth := &azpim.Authenticator{
				TenantID: "tenant-1",
				ClientID: "client-1",
				Endpoint: stub.server.URL,
				CacheDir: t.TempDir(),
				Browser:  browser(t, &challenge, nil),
			}

			_, err := auth.Token(context.Background(), []string{"openid"})

			assert.ErrorContains(err, tt.errMsg)
		})
	}
}

// TestAuthenticatorRefreshRejectedFallsBackToSignIn covers a refresh token the
// tenant no longer honours, which is what a revoked session or an expired
// sign-in frequency window looks like. It has to lead to a sign-in rather than
// to a failure.
func TestAuthenticatorRefreshRejectedFallsBackToSignIn(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := t.TempDir()
	scopes := []string{"openid"}
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
		"refresh_token": "no-longer-valid",
		"expires_at":    time.Now().Add(-time.Hour).Unix(),
	})

	stub.replies = map[string]string{
		"refresh_token":      `{"error":"invalid_grant","error_description":"token revoked"}`,
		"authorization_code": `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`,
	}

	signIns := 0
	auth.Browser = func(target string) error {
		signIns++

		return browser(t, &challenge, nil)(target)
	}

	token, err := auth.Token(context.Background(), scopes)

	assert.NoError(err)
	assert.Equal("access-2", token)
	assert.Equal(1, signIns)
}

// TestAuthenticatorTokenEndpointUnreachable covers the network being gone at
// redemption time, after the browser half has already succeeded.
func TestAuthenticatorTokenEndpointUnreachable(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{}`)
	stub.server.Close()

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.Error(err)
}

// TestAuthenticatorDefaultCacheDir covers the path used in real runs, where no
// cache directory is configured and the OS convention decides.
func TestAuthenticatorDefaultCacheDir(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		Browser:  browser(t, &challenge, nil),
	}

	token, err := auth.Token(context.Background(), []string{"openid"})

	require.NoError(t, err)
	assert.Equal("access-1", token)

	base, err := os.UserCacheDir()
	require.NoError(t, err)

	assert.Len(accessEntries(t, filepath.Join(base, "azpim")), 1)
}

// TestAuthenticatorCacheUnwritable covers a cache directory that cannot be
// created. The token was obtained, but failing to persist it silently would
// mean signing in again on every command with no explanation.
func TestAuthenticatorCacheUnwritable(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: filepath.Join(blocker, "cache"),
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.Error(err)
}

// TestAuthenticatorSignInCancelled covers the caller giving up while the
// browser half is still outstanding.
func TestAuthenticatorSignInCancelled(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		// Nothing ever comes back through the redirect.
		Browser: func(string) error { return nil },
	}

	_, err := auth.Token(ctx, []string{"openid"})

	assert.ErrorIs(err, context.Canceled)
}

// TestAuthenticatorBrowserFails covers a machine with no way to open a browser.
func TestAuthenticatorBrowserFails(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{}`)

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		Browser:  func(string) error { return errors.New("no browser available") },
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.ErrorContains(err, "no browser available")
}

// TestAuthenticatorUsesSuppliedHTTPClient covers a caller providing its own
// transport, which is then used for the token endpoint too.
func TestAuthenticatorUsesSuppliedHTTPClient(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
		HTTP:     stub.server.Client(),
		Browser:  browser(t, &challenge, nil),
	}

	client, err := auth.Client(context.Background(), []string{"openid"})

	require.NoError(t, err)
	assert.Equal("access-1", client.Token)
}

// TestAuthenticatorIgnoresUnreadableCache covers a cache file left behind in a
// state that cannot be parsed. It must lead to a sign-in, not to a failure.
func TestAuthenticatorIgnoresUnreadableCache(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := t.TempDir()
	scopes := []string{"openid"}
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), scopes)
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	// Both the access token and the refresh token are corrupted, so that
	// nothing on disk can be salvaged and signing in again is the only way
	// left to answer.
	for _, entry := range entries {
		require.NoError(t, os.WriteFile(filepath.Join(dir, entry.Name()), []byte("{not json"), 0o600))
	}

	token, err := auth.Token(context.Background(), scopes)

	assert.NoError(err)
	assert.Equal("access-1", token)
}

// TestAuthenticatorNoHomeDirectory covers a process with no home directory to
// derive a default cache location from.
func TestAuthenticatorNoHomeDirectory(t *testing.T) {
	assert := assert.New(t)

	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")

	auth := &azpim.Authenticator{TenantID: "tenant-1", ClientID: "client-1"}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.Error(err)
}

// TestAuthenticatorCacheFileUnwritable covers a cache directory that exists but
// cannot be written into.
func TestAuthenticatorCacheFileUnwritable(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	dir := filepath.Join(t.TempDir(), "cache")
	require.NoError(t, os.MkdirAll(dir, 0o500))

	var challenge string

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.Error(err)
}

// TestAuthenticatorRefreshFileUnwritable covers the refresh token's own entry
// failing to be written while the access token's succeeded. Reporting the
// access token as though it were filed would mean claiming a sign-in was
// remembered when the part that makes it silent next time was lost.
func TestAuthenticatorRefreshFileUnwritable(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := t.TempDir()
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.Token(context.Background(), azpim.RoleScopes)
	require.NoError(t, err)

	// Put a directory where the refresh token goes, which nothing can be
	// renamed over. Its name is only knowable by elimination, since the file
	// names are digests.
	access := accessEntries(t, dir)
	require.Len(t, access, 1)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.Name() == access[0] {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Mkdir(path, 0o700))
	}

	// A different area, so the access token is written afresh and the refresh
	// token is what fails.
	_, err = auth.Token(context.Background(), azpim.GroupScopes)

	assert.Error(err)
}

// TestAuthenticatorTokenWithoutRefresh covers a reply carrying no refresh
// token, which is what a scope set without offline_access is answered with.
// The access token is still worth keeping for as long as it lives; there is
// simply nothing to renew it with once it has expired.
func TestAuthenticatorTokenWithoutRefresh(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","expires_in":3600}`)

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

	token, err := auth.Token(context.Background(), scopes)

	require.NoError(t, err)
	assert.Equal("access-1", token)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(entries, 1, "nothing is filed under the refresh token's key")

	auth.Browser = func(string) error {
		t.Error("a cached token should not trigger a sign-in")

		return nil
	}

	token, err = auth.Token(context.Background(), scopes)

	assert.NoError(err)
	assert.Equal("access-1", token)
}

// TestAuthenticatorTokenWithClaims covers the sign-in that answers a claims
// challenge: the claims travel with the authorization request, which is what
// lets the identity platform stamp the acrs claim PIM checks for.
func TestAuthenticatorTokenWithClaims(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-acrs","refresh_token":"refresh-1","expires_in":3600}`)

	var seen url.Values

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
	}

	auth.Browser = func(target string) error {
		parsed, err := url.Parse(target)
		require.NoError(t, err)

		seen = parsed.Query()

		var challenge string

		return browser(t, &challenge, nil)(target)
	}

	claims := `{"access_token":{"acrs":{"essential":true, "value":"c1"}}}`
	token, err := auth.TokenWithClaims(context.Background(), []string{"openid"}, claims)

	assert.NoError(err)
	assert.Equal("access-acrs", token)
	assert.Equal(claims, seen.Get("claims"))
}

// TestAuthenticatorTokenWithoutClaims checks that an ordinary sign-in asks for
// no authentication context. Demanding one unprompted would fail in a tenant
// that has not defined it, and prompt for nothing in one that has.
func TestAuthenticatorTokenWithoutClaims(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var seen url.Values

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
	}

	auth.Browser = func(target string) error {
		parsed, err := url.Parse(target)
		require.NoError(t, err)

		seen = parsed.Query()

		var challenge string

		return browser(t, &challenge, nil)(target)
	}

	_, err := auth.Token(context.Background(), []string{"openid"})

	assert.NoError(err)
	assert.Empty(seen.Get("claims"))
}

// TestAuthenticatorClaimsKeyTheCache covers a challenged token being filed
// apart from a plain one, and reused on its own terms.
func TestAuthenticatorClaimsKeyTheCache(t *testing.T) {
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

	claims := `{"access_token":{"acrs":{"essential":true, "value":"c1"}}}`

	_, err := auth.Token(context.Background(), []string{"openid"})
	require.NoError(t, err)

	_, err = auth.TokenWithClaims(context.Background(), []string{"openid"}, claims)
	require.NoError(t, err)

	// The plain token cannot stand in for the challenged one, and neither can
	// the refresh token behind it, since a refresh cannot produce the acrs
	// claim being asked for. So the challenge costs a sign-in of its own even
	// though one has already happened.
	assert.Equal(2, signIns)

	assert.Len(accessEntries(t, dir), 2, "a challenged token gets its own cache entry")

	// A second activation within the token's life reuses it rather than
	// opening the browser again.
	_, err = auth.TokenWithClaims(context.Background(), []string{"openid"}, claims)
	require.NoError(t, err)

	assert.Equal(2, signIns)
}

// TestAuthenticatorClaimsSkipsRefresh covers a challenge arriving while a
// refresh token is on hand. Redeeming it would produce a token without the
// acrs claim, which is the one thing the caller cannot use.
func TestAuthenticatorClaimsSkipsRefresh(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var challenge string

	dir := t.TempDir()
	claims := `{"access_token":{"acrs":{"essential":true, "value":"c1"}}}`
	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: dir,
		Browser:  browser(t, &challenge, nil),
	}

	_, err := auth.TokenWithClaims(context.Background(), []string{"openid"}, claims)
	require.NoError(t, err)

	// Age the cached token past its life, leaving a refresh token behind.
	writeCachedToken(t, dir, map[string]any{
		"access_token":  "stale",
		"refresh_token": "refresh-1",
		"expires_at":    time.Now().Add(-time.Hour).Unix(),
	})

	_, err = auth.TokenWithClaims(context.Background(), []string{"openid"}, claims)

	assert.NoError(err)
	assert.Equal("authorization_code", stub.form.Get("grant_type"))
}

// TestAuthenticatorClientReauth covers the way back from a challenged call to
// a sign-in: the client the commands hold has to be able to ask for a token
// carrying the claims, for the same scopes it was built with.
func TestAuthenticatorClientReauth(t *testing.T) {
	assert := assert.New(t)
	stub := newTokenStub(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)

	var seen url.Values

	auth := &azpim.Authenticator{
		TenantID: "tenant-1",
		ClientID: "client-1",
		Endpoint: stub.server.URL,
		CacheDir: t.TempDir(),
	}

	auth.Browser = func(target string) error {
		parsed, err := url.Parse(target)
		require.NoError(t, err)

		seen = parsed.Query()

		var challenge string

		return browser(t, &challenge, nil)(target)
	}

	client, err := auth.Client(context.Background(), []string{"openid", "Scope.One"})
	require.NoError(t, err)
	require.NotNil(t, client.Reauth)

	stub.reply = `{"access_token":"access-acrs","refresh_token":"refresh-1","expires_in":3600}`
	claims := `{"access_token":{"acrs":{"essential":true, "value":"c1"}}}`

	token, err := client.Reauth(context.Background(), claims)

	assert.NoError(err)
	assert.Equal("access-acrs", token)
	assert.Equal(claims, seen.Get("claims"))
	assert.Equal("openid Scope.One", seen.Get("scope"), "the challenge is answered for the scopes the client holds")
}
